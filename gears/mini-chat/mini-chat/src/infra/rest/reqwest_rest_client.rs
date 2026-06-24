//! `reqwest`-backed [`RestClient`] adapter with built-in SSRF safeguards.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use reqwest::header::{HeaderName, HeaderValue};
use toolkit_security::SecurityContext;
use tracing::{debug, warn};

use crate::config::RestAPIToolConfig;
use crate::domain::ports::rest_client::{RestClient, RestError, RestMethod, RestRequest, RestResponse};

/// HTTP request/response header names that must never be set by a connector
/// (hop-by-hop or framing-controlled). Compared case-insensitively.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "keep-alive",
    "te",
    "trailer",
];

/// Direct-`reqwest` REST transport. Holds a single client (timeout +
/// no-redirect + no-proxy) plus the resolved host allowlist and byte cap.
pub struct ReqwestRestClient {
    client: reqwest::Client,
    allowed_hosts: HashSet<String>,
    max_response_bytes: usize,
    /// Whether to reject private/loopback/link-local/metadata IPs. `true` by
    /// default; set to `false` via `allow_private_ips` in config when connectors
    /// must reach internal/corporate hosts, or by the test constructor so adapter
    /// tests can hit a local `httpmock` server on `127.0.0.1`.
    block_local_ips: bool,
}

impl std::fmt::Debug for ReqwestRestClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqwestRestClient")
            .field("allowed_hosts", &self.allowed_hosts.len())
            .field("max_response_bytes", &self.max_response_bytes)
            .field("block_local_ips", &self.block_local_ips)
            .finish_non_exhaustive()
    }
}

impl ReqwestRestClient {
    /// Build the client and derive the host allowlist from connector base URLs.
    ///
    /// # Errors
    /// Returns [`RestError::Configuration`] if the underlying `reqwest` client
    /// cannot be constructed.
    pub fn new(cfg: &RestAPIToolConfig) -> Result<Self, RestError> {
        let mut allowed_hosts = HashSet::new();
        for c in &cfg.connectors {
            if let Ok(url) = url::Url::parse(&c.base_url)
                && let Some(host) = url.host_str()
            {
                allowed_hosts.insert(host.to_ascii_lowercase());
            }
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| RestError::Configuration(format!("failed to build reqwest client: {e}")))?;

        Ok(Self {
            client,
            allowed_hosts,
            max_response_bytes: cfg.max_response_bytes,
            block_local_ips: !cfg.allow_private_ips,
        })
    }

    /// Test-only constructor that disables IP blocking so adapter tests can
    /// reach a local `httpmock` server. `allowed_hosts` must still match.
    #[cfg(test)]
    fn for_test(allowed_hosts: HashSet<String>, max_response_bytes: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("test client builds");
        Self {
            client,
            allowed_hosts,
            max_response_bytes,
            block_local_ips: false,
        }
    }
}

#[async_trait]
impl RestClient for ReqwestRestClient {
    async fn call(
        &self,
        _ctx: SecurityContext,
        req: RestRequest,
    ) -> Result<RestResponse, RestError> {
        let mut current_url = url::Url::parse(&req.url)
            .map_err(|e| RestError::Rejected(format!("invalid url '{}': {e}", req.url)))?;

        self.validate_url(&current_url)?;
        self.validate_host_ip(&current_url).await?;

        let method = match req.method {
            RestMethod::Get => reqwest::Method::GET,
            RestMethod::Post => reqwest::Method::POST,
        };

        // Pre-parse headers once so they can be re-applied on every redirect.
        let headers = Self::parse_headers(sanitize_headers(req.headers));

        // ── Redirect loop ──
        // Auto-redirects are disabled on the reqwest client (Policy::none) so
        // that we can re-apply ALL original headers — including Authorization
        // and X-Zero-Trust-Token — on every hop. reqwest's built-in redirect
        // handling strips sensitive headers by design.
        const MAX_REDIRECTS: usize = 5;
        for hop in 0..=MAX_REDIRECTS {
            let mut builder = self.client.request(method.clone(), current_url.clone());
            for (n, v) in &headers {
                builder = builder.header(n.clone(), v.clone());
            }
            // Attach the body only on the initial request.
            if hop == 0 {
                if let Some(ref body) = req.body {
                    builder = builder.json(body);
                }
            }

            let resp = builder
                .send()
                .await
                .map_err(|e| RestError::Unavailable(format!("request failed: {e}")))?;

            let status = resp.status().as_u16();

            if !(300..400).contains(&status) {
                // Non-redirect — read body and return.
                return self.read_response(resp, status).await;
            }

            // ── Handle redirect ──
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();

            if location.is_empty() || hop == MAX_REDIRECTS {
                let detail = if location.is_empty() {
                    "(no Location header)".to_owned()
                } else {
                    format!("too many redirects ({MAX_REDIRECTS})")
                };
                let ct = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(ToOwned::to_owned);
                return Ok(RestResponse {
                    status,
                    content_type: ct,
                    body_text: format!("Redirect ({status}): {detail} (not followed)"),
                    truncated: false,
                });
            }

            // Resolve relative Location against the current URL.
            let next = current_url.join(&location).map_err(|e| {
                RestError::Unavailable(format!("invalid redirect location '{location}': {e}"))
            })?;

            // Validate redirect target against the host allowlist.
            let rhost = next
                .host_str()
                .ok_or_else(|| {
                    RestError::Rejected("redirect url has no host".to_owned())
                })?
                .to_ascii_lowercase();
            if !self.allowed_hosts.contains(&rhost) {
                warn!(
                    from = %current_url, to = %next, host = %rhost,
                    "redirect target not on allowlist; stopping"
                );
                let ct = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(ToOwned::to_owned);
                return Ok(RestResponse {
                    status,
                    content_type: ct,
                    body_text: format!(
                        "Redirect ({status}) to: {next} (not followed — host not on allowlist)"
                    ),
                    truncated: false,
                });
            }

            debug!(hop, from = %current_url, to = %next, "following same-host redirect");
            current_url = next;
        }

        Err(RestError::Unavailable(
            "exceeded maximum redirect hops".to_owned(),
        ))
    }
}

impl ReqwestRestClient {
    /// Validate URL scheme and host against the allowlist.
    fn validate_url(&self, url: &url::Url) -> Result<(), RestError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(RestError::Rejected(format!(
                "scheme '{}' not allowed",
                url.scheme()
            )));
        }
        let host = url
            .host_str()
            .ok_or_else(|| RestError::Rejected("url has no host".to_owned()))?
            .to_ascii_lowercase();
        if !self.allowed_hosts.contains(&host) {
            warn!(host = %host, "rest connector host not on allowlist; rejecting");
            return Err(RestError::Rejected(format!(
                "host '{host}' is not on the connector allowlist"
            )));
        }
        Ok(())
    }

    /// Resolve DNS and block disallowed IPs (private/loopback/link-local/metadata).
    async fn validate_host_ip(&self, url: &url::Url) -> Result<(), RestError> {
        let host = url
            .host_str()
            .ok_or_else(|| RestError::Rejected("url has no host".to_owned()))?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| RestError::Rejected("could not determine port".to_owned()))?;
        let addrs = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| RestError::Unavailable(format!("dns resolution failed: {e}")))?;
        let mut any = false;
        for addr in addrs {
            any = true;
            if self.block_local_ips && ip_is_blocked(addr.ip()) {
                warn!(host = %host, ip = %addr.ip(), "resolved IP is blocked; rejecting");
                return Err(RestError::Rejected(format!(
                    "host '{host}' resolves to a disallowed address"
                )));
            }
        }
        if !any {
            return Err(RestError::Unavailable(format!(
                "host '{host}' did not resolve to any address"
            )));
        }
        Ok(())
    }

    /// Pre-parse header name/value pairs, skipping any that are invalid.
    fn parse_headers(
        raw: Vec<(String, String)>,
    ) -> Vec<(HeaderName, HeaderValue)> {
        raw.into_iter()
            .filter_map(|(name, value)| {
                match (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    (Ok(n), Ok(v)) => Some((n, v)),
                    _ => {
                        debug!(header = %name, "skipping invalid connector header");
                        None
                    }
                }
            })
            .collect()
    }

    /// Read the response body up to the configured byte cap.
    async fn read_response(
        &self,
        resp: reqwest::Response,
        status: u16,
    ) -> Result<RestResponse, RestError> {
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        let mut stream = resp.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|e| RestError::Unavailable(format!("body read failed: {e}")))?;
            let remaining = self.max_response_bytes.saturating_sub(buf.len());
            if chunk.len() > remaining {
                buf.extend_from_slice(&chunk[..remaining]);
                truncated = true;
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        let body_text = String::from_utf8_lossy(&buf).into_owned();

        Ok(RestResponse {
            status,
            content_type,
            body_text,
            truncated,
        })
    }
}

/// Strip reserved/hop-by-hop headers a connector must not control.
pub fn sanitize_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            !RESERVED_HEADERS.contains(&lower.as_str()) && !lower.starts_with("proxy-")
        })
        .collect()
}

/// Whether the host string is on the allowlist (exact, case-insensitive).
#[cfg_attr(not(test), allow(dead_code))]
pub fn host_allowed(url: &str, allowlist: &HashSet<String>) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|h| allowlist.contains(&h))
}

/// Whether an IP must be blocked as an SSRF target (private / loopback /
/// link-local / unspecified / unique-local / CGNAT / cloud metadata).
pub fn ip_is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 0.0.0.0/8
                || o[0] == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ip_is_blocked(IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local
                || (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn sanitize_strips_reserved_and_proxy_headers() {
        let headers = vec![
            ("Authorization".to_owned(), "Bearer x".to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
            ("Host".to_owned(), "evil.example".to_owned()),
            ("Content-Length".to_owned(), "10".to_owned()),
            ("Proxy-Authorization".to_owned(), "creds".to_owned()),
            ("Connection".to_owned(), "keep-alive".to_owned()),
        ];
        let out = sanitize_headers(headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"Authorization"));
        assert!(names.contains(&"Accept"));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("host")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("content-length")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("proxy-authorization")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("connection")));
    }

    #[test]
    fn blocks_private_loopback_and_metadata_ips() {
        assert!(ip_is_blocked(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(ip_is_blocked(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(ip_is_blocked(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(ip_is_blocked(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        // cloud metadata (link-local)
        assert!(ip_is_blocked(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(ip_is_blocked(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(ip_is_blocked(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // fc00::/7 unique local
        assert!(ip_is_blocked("fc00::1".parse().unwrap()));
        // fe80::/10 link-local
        assert!(ip_is_blocked("fe80::1".parse().unwrap()));
    }

    #[test]
    fn allows_public_ips() {
        assert!(!ip_is_blocked(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!ip_is_blocked("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()));
    }

    #[test]
    fn host_allowed_matches_case_insensitively() {
        let mut allow = HashSet::new();
        allow.insert("adn.acronis.com".to_owned());
        assert!(host_allowed("https://ADN.Acronis.com/wiki", &allow));
        assert!(!host_allowed("https://evil.example/path", &allow));
        assert!(!host_allowed("not a url", &allow));
    }

    #[tokio::test]
    async fn outbound_request_carries_configured_headers_and_strips_reserved() {
        use httpmock::MockServer;

        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET)
                    .path("/wiki/rest/api/search")
                    .header("Accept", "application/json")
                    .header("X-Atlassian-Token", "no-check");
                then.status(200)
                    .header("content-type", "application/json")
                    .body("{\"ok\":true}");
            })
            .await;

        // httpmock listens on 127.0.0.1 — allow it and use the test constructor
        // that disables IP blocking.
        let mut allow = HashSet::new();
        allow.insert("127.0.0.1".to_owned());
        let client = ReqwestRestClient::for_test(allow, 32_768);

        let req = RestRequest {
            method: RestMethod::Get,
            url: format!("{}/wiki/rest/api/search?cql=text", server.base_url()),
            query: vec![],
            headers: vec![
                ("Accept".to_owned(), "application/json".to_owned()),
                ("X-Atlassian-Token".to_owned(), "no-check".to_owned()),
                // Reserved header — must be stripped before send.
                ("Host".to_owned(), "evil.example".to_owned()),
            ],
            body: None,
        };

        let resp = client
            .call(SecurityContext::anonymous(), req)
            .await
            .expect("request succeeds");
        assert_eq!(resp.status, 200);
        assert!(resp.body_text.contains("ok"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn redirect_preserves_auth_headers() {
        use httpmock::MockServer;

        let server = MockServer::start_async().await;

        // First request returns 302 redirect to /final.
        let redirect_mock = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET).path("/start");
                then.status(302).header("Location", "/final");
            })
            .await;

        // Second request (after redirect) must carry the same auth headers.
        let final_mock = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET)
                    .path("/final")
                    .header("Authorization", "Bearer tok123")
                    .header("X-Zero-Trust-Token", "zt456");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(r#"{"found":true}"#);
            })
            .await;

        let mut allow = HashSet::new();
        allow.insert("127.0.0.1".to_owned());
        let client = ReqwestRestClient::for_test(allow, 32_768);

        let req = RestRequest {
            method: RestMethod::Get,
            url: format!("{}/start", server.base_url()),
            query: vec![],
            headers: vec![
                ("Authorization".to_owned(), "Bearer tok123".to_owned()),
                ("X-Zero-Trust-Token".to_owned(), "zt456".to_owned()),
            ],
            body: None,
        };

        let resp = client
            .call(SecurityContext::anonymous(), req)
            .await
            .expect("request succeeds after redirect");
        assert_eq!(resp.status, 200);
        assert!(resp.body_text.contains("found"));
        redirect_mock.assert_async().await;
        final_mock.assert_async().await;
    }

    #[tokio::test]
    async fn rejects_host_not_on_allowlist() {
        let client = ReqwestRestClient::for_test(HashSet::new(), 32_768);
        let req = RestRequest {
            method: RestMethod::Get,
            url: "https://evil.example/x".to_owned(),
            query: vec![],
            headers: vec![],
            body: None,
        };
        let err = client
            .call(SecurityContext::anonymous(), req)
            .await
            .unwrap_err();
        assert!(matches!(err, RestError::Rejected(_)));
    }
}
