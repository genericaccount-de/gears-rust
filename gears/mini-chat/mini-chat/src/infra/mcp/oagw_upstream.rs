//! OAGW upstream + route lifecycle for MCP servers.
//!
//! Every MCP server has a matching OAGW upstream and a catch-all route. The
//! upstream alias is **owned by OAGW**: for hostname endpoints it is
//! auto-derived (host, or `host:port` for non-standard ports) and a
//! caller-supplied alias that differs is rejected; IP endpoints instead
//! *require* an explicit alias, for which we use the deterministic
//! `mcp-{server_id}`. The alias OAGW returns is what mini-chat uses to route.
//!
//! Mini-chat never resolves secrets: each [`McpAuth`] variant maps to an OAGW
//! built-in auth plugin, and OAGW resolves the referenced credstore secret
//! using the caller's `SecurityContext`.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use oagw_sdk::{
    AuthConfig, CreateRouteRequest, CreateUpstreamRequest, Endpoint, HeadersConfig, HttpMatch,
    HttpMethod, ListQuery, MatchRules, PassthroughMode, PathSuffixMode, RequestHeaderRules, Scheme,
    Server, ServiceGatewayClientV1, SharingMode, Upstream, UpdateUpstreamRequest,
};
use toolkit_security::SecurityContext;

use super::error::{McpError, McpResult};
use super::types::{
    HEADER_MCP_PROTOCOL_VERSION, HEADER_MCP_SESSION_ID, HEADER_OAGW_TARGET_HOST, McpAuth,
};

const HTTP_PROTOCOL: &str = "gts.cf.core.oagw.protocol.v1~cf.core.oagw.http.v1";
const PLUGIN_NOOP: &str = "gts.cf.core.oagw.auth_plugin.v1~cf.core.oagw.noop.v1";
const PLUGIN_APIKEY: &str = "gts.cf.core.oagw.auth_plugin.v1~cf.core.oagw.apikey.v1";
const PLUGIN_OAUTH2: &str = "gts.cf.core.oagw.auth_plugin.v1~cf.core.oagw.oauth2_client_cred.v1";
const PLUGIN_OAUTH2_AUTH_CODE: &str =
    "gts.cf.core.oagw.auth_plugin.v1~cf.core.oagw.oauth2_auth_code.v1";

/// Deterministic credstore key for the per-user OAuth token record of an MCP
/// server. Shared by the OAGW auth-code plugin binding (which reads it) and
/// the management API that provisions the token (which writes it).
#[must_use]
pub fn oauth_token_ref(server_id: &str) -> String {
    format!("mcp_oauth_{server_id}")
}

/// Parsed components of an MCP server URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMcpUrl {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Path component forwarded verbatim by the catch-all route.
    pub base_path: String,
}

/// Parse an MCP server URL into OAGW endpoint components.
pub fn parse_mcp_url(url: &str) -> McpResult<ParsedMcpUrl> {
    let uri = http::Uri::from_str(url)
        .map_err(|e| McpError::Protocol(format!("invalid MCP server URL '{url}': {e}")))?;

    let scheme_str = uri
        .scheme_str()
        .ok_or_else(|| McpError::Protocol(format!("MCP server URL '{url}' missing scheme")))?;
    let scheme = match scheme_str {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        other => {
            return Err(McpError::Protocol(format!(
                "unsupported MCP scheme '{other}' (only http/https)"
            )));
        }
    };

    let host = uri
        .host()
        .ok_or_else(|| McpError::Protocol(format!("MCP server URL '{url}' missing host")))?
        .to_owned();

    let port = uri
        .port_u16()
        .unwrap_or(if scheme == Scheme::Https { 443 } else { 80 });

    // Preserve the path verbatim, including any trailing slash: some MCP
    // servers mount their endpoint at `/mcp/` and issue a 307 redirect when
    // requested at `/mcp`. A bare root path (`/`) carries no routing
    // information, so it collapses to empty (transport then targets
    // `/{alias}`).
    let path = uri.path();
    let base_path = if path == "/" {
        String::new()
    } else {
        path.to_owned()
    };

    Ok(ParsedMcpUrl {
        scheme,
        host,
        port,
        base_path,
    })
}

/// Deterministic OAGW alias for an MCP server. Only used for IP-based
/// endpoints, where OAGW requires an explicit alias (hostname endpoints get an
/// auto-derived alias instead).
#[must_use]
pub fn alias_for(server_id: &str) -> String {
    format!("mcp-{server_id}")
}

/// Whether `host` is an IP literal (IPv4/IPv6). OAGW auto-derives aliases only
/// for hostname endpoints; IP endpoints require an explicit alias.
fn is_ip_host(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok()
}

/// Resolve the OAGW alias for an MCP endpoint.
///
/// Returns `(routing_alias, explicit_alias)`:
/// - `routing_alias` — the alias mini-chat expects OAGW to assign, used to
///   locate an existing upstream (`ensure`). For hostname endpoints this is the
///   OAGW-derived value ([`Endpoint::alias_contribution`]); for IP endpoints it
///   is `mcp-{server_id}`.
/// - `explicit_alias` — `Some` only when the alias must be sent on the request
///   (IP endpoints). For hostname endpoints it is `None`, since sending a
///   differing alias is rejected by OAGW.
fn derive_alias(parsed: &ParsedMcpUrl, server_id: &str) -> (String, Option<String>) {
    if is_ip_host(&parsed.host) {
        let alias = alias_for(server_id);
        (alias.clone(), Some(alias))
    } else {
        let endpoint = Endpoint {
            scheme: parsed.scheme,
            host: parsed.host.clone(),
            port: parsed.port,
        };
        (endpoint.alias_contribution(), None)
    }
}

/// Map an [`McpAuth`] to the corresponding OAGW auth-plugin configuration.
///
/// `server_id` and `resource` are used only by the interactive
/// authorization-code variant to derive the per-user token store key and the
/// protected-resource identifier surfaced on re-authorization.
#[must_use]
pub fn auth_config_for(auth: &McpAuth, server_id: &str, resource: &str) -> AuthConfig {
    match auth {
        McpAuth::None => AuthConfig {
            plugin_type: PLUGIN_NOOP.to_owned(),
            sharing: SharingMode::Inherit,
            config: None,
        },
        McpAuth::Bearer { secret_ref } => AuthConfig {
            plugin_type: PLUGIN_APIKEY.to_owned(),
            sharing: SharingMode::Inherit,
            config: Some(HashMap::from([
                ("header".to_owned(), "authorization".to_owned()),
                ("prefix".to_owned(), "Bearer ".to_owned()),
                ("secret_ref".to_owned(), secret_ref.clone()),
            ])),
        },
        McpAuth::ApiKey { header, secret_ref } => AuthConfig {
            plugin_type: PLUGIN_APIKEY.to_owned(),
            sharing: SharingMode::Inherit,
            config: Some(HashMap::from([
                ("header".to_owned(), header.clone()),
                ("prefix".to_owned(), String::new()),
                ("secret_ref".to_owned(), secret_ref.clone()),
            ])),
        },
        McpAuth::OAuth2 {
            client_id_ref,
            client_secret_ref,
            token_url,
            scopes,
        } => AuthConfig {
            plugin_type: PLUGIN_OAUTH2.to_owned(),
            sharing: SharingMode::Inherit,
            config: Some(HashMap::from([
                ("token_endpoint".to_owned(), token_url.clone()),
                ("client_id_ref".to_owned(), client_id_ref.clone()),
                ("client_secret_ref".to_owned(), client_secret_ref.clone()),
                ("scopes".to_owned(), scopes.join(" ")),
            ])),
        },
        McpAuth::OAuth2AuthorizationCode { scopes } => AuthConfig {
            plugin_type: PLUGIN_OAUTH2_AUTH_CODE.to_owned(),
            sharing: SharingMode::Inherit,
            config: Some(HashMap::from([
                ("token_ref".to_owned(), oauth_token_ref(server_id)),
                ("resource".to_owned(), resource.to_owned()),
                ("scopes".to_owned(), scopes.join(" ")),
            ])),
        },
    }
}

/// Header passthrough allowlist required for MCP session + affinity headers.
///
/// `Accept` must be forwarded: MCP Streamable HTTP servers require it to list
/// both `application/json` and `text/event-stream` and return `406 Not
/// Acceptable` otherwise. `Content-Type` is always forwarded by OAGW and needs
/// no allowlist entry.
fn mcp_headers_config() -> HeadersConfig {
    HeadersConfig {
        request: Some(RequestHeaderRules {
            passthrough: PassthroughMode::Allowlist,
            passthrough_allowlist: vec![
                http::header::ACCEPT.as_str().to_owned(),
                HEADER_MCP_PROTOCOL_VERSION.to_owned(),
                HEADER_MCP_SESSION_ID.to_owned(),
                HEADER_OAGW_TARGET_HOST.to_owned(),
            ],
            ..Default::default()
        }),
        response: None,
    }
}

fn server_from(parsed: &ParsedMcpUrl) -> Server {
    Server {
        endpoints: vec![Endpoint {
            scheme: parsed.scheme,
            host: parsed.host.clone(),
            port: parsed.port,
        }],
    }
}

fn tags_for(server_id: &str) -> Vec<String> {
    vec!["mcp".to_owned(), format!("mcp-server:{server_id}")]
}

/// Result of provisioning an MCP server's OAGW upstream.
#[derive(Debug, Clone)]
pub struct ProvisionedUpstream {
    pub upstream_id: String,
    pub alias: String,
    pub base_path: String,
}

/// Create the OAGW upstream + catch-all route for a new MCP server.
pub async fn create(
    gateway: &Arc<dyn ServiceGatewayClientV1>,
    ctx: &SecurityContext,
    server_id: &str,
    url: &str,
    auth: &McpAuth,
    enabled: bool,
) -> McpResult<ProvisionedUpstream> {
    let parsed = parse_mcp_url(url)?;
    let (_routing_alias, explicit_alias) = derive_alias(&parsed, server_id);

    let mut builder = CreateUpstreamRequest::builder(server_from(&parsed), HTTP_PROTOCOL)
        .enabled(enabled)
        .auth(auth_config_for(auth, server_id, url))
        .headers(mcp_headers_config())
        .tags(tags_for(server_id));
    // Hostname endpoints: alias is auto-derived by OAGW (sending one is
    // rejected). IP endpoints: an explicit alias is required.
    if let Some(alias) = explicit_alias {
        builder = builder.alias(alias);
    }
    let upstream_req = builder.build();

    let upstream = gateway
        .create_upstream(ctx.clone(), upstream_req)
        .await
        .map_err(|e| McpError::Transport(format!("create_upstream failed: {e}")))?;

    let route_req = CreateRouteRequest::builder(
        upstream.id,
        MatchRules {
            http: Some(HttpMatch {
                methods: vec![HttpMethod::Post, HttpMethod::Get, HttpMethod::Delete],
                path: "/".to_owned(),
                query_allowlist: vec![],
                path_suffix_mode: PathSuffixMode::Append,
            }),
            grpc: None,
        },
    )
    .enabled(enabled)
    .tags(tags_for(server_id))
    .build();

    gateway
        .create_route(ctx.clone(), route_req)
        .await
        .map_err(|e| McpError::Transport(format!("create_route failed: {e}")))?;

    Ok(ProvisionedUpstream {
        upstream_id: upstream.id.to_string(),
        // Use the alias OAGW actually assigned (authoritative for routing).
        alias: upstream.alias,
        base_path: parsed.base_path,
    })
}

/// Replace an existing upstream (PUT semantics) — used for URL/auth updates and
/// enable/disable toggles.
///
/// Returns the parsed URL and the alias OAGW assigned (authoritative for
/// routing).
pub async fn update(
    gateway: &Arc<dyn ServiceGatewayClientV1>,
    ctx: &SecurityContext,
    upstream_id: &str,
    server_id: &str,
    url: &str,
    auth: &McpAuth,
    enabled: bool,
) -> McpResult<(ParsedMcpUrl, String)> {
    let id = uuid::Uuid::from_str(upstream_id)
        .map_err(|e| McpError::Protocol(format!("invalid upstream id '{upstream_id}': {e}")))?;
    let parsed = parse_mcp_url(url)?;
    let (_routing_alias, explicit_alias) = derive_alias(&parsed, server_id);

    let mut builder = UpdateUpstreamRequest::builder(server_from(&parsed), HTTP_PROTOCOL)
        .enabled(enabled)
        .auth(auth_config_for(auth, server_id, url))
        .headers(mcp_headers_config())
        .tags(tags_for(server_id));
    // Hostname endpoints: alias is auto-derived (omitting keeps it). IP
    // endpoints: an explicit alias is required.
    if let Some(alias) = explicit_alias {
        builder = builder.alias(alias);
    }
    let req = builder.build();

    let upstream = gateway
        .update_upstream(ctx.clone(), id, req)
        .await
        .map_err(|e| McpError::Transport(format!("update_upstream failed: {e}")))?;

    Ok((parsed, upstream.alias))
}

/// Idempotently provision an upstream: reuse the one already matching the
/// deterministic alias (updating its URL/auth/enabled), otherwise create it.
///
/// The SDK's `create_upstream` is **not** idempotent (a duplicate alias yields
/// a `Conflict`) and there is no get-by-alias, so a prior upstream is located
/// by paging `list_upstreams`. Used by hub sync, where no DB row remembers the
/// hub's upstream id across restarts.
pub async fn ensure(
    gateway: &Arc<dyn ServiceGatewayClientV1>,
    ctx: &SecurityContext,
    server_id: &str,
    url: &str,
    auth: &McpAuth,
    enabled: bool,
) -> McpResult<ProvisionedUpstream> {
    let parsed = parse_mcp_url(url)?;
    let (routing_alias, _) = derive_alias(&parsed, server_id);
    match find_by_alias(gateway, ctx, &routing_alias).await? {
        Some(existing) => {
            let upstream_id = existing.id.to_string();
            let (parsed, alias) =
                update(gateway, ctx, &upstream_id, server_id, url, auth, enabled).await?;
            Ok(ProvisionedUpstream {
                upstream_id,
                alias,
                base_path: parsed.base_path,
            })
        }
        None => create(gateway, ctx, server_id, url, auth, enabled).await,
    }
}

/// Locate an upstream by its (tenant-scoped) alias, paging `list_upstreams`.
async fn find_by_alias(
    gateway: &Arc<dyn ServiceGatewayClientV1>,
    ctx: &SecurityContext,
    alias: &str,
) -> McpResult<Option<Upstream>> {
    /// Page size for the alias scan.
    const PAGE: u32 = 100;
    /// Upper bound on pages scanned to avoid an unbounded loop.
    const MAX_PAGES: u32 = 100;

    let mut skip = 0;
    for _ in 0..MAX_PAGES {
        let query = ListQuery { top: PAGE, skip };
        let page = gateway
            .list_upstreams(ctx.clone(), &query)
            .await
            .map_err(|e| McpError::Transport(format!("list_upstreams failed: {e}")))?;
        let count = u32::try_from(page.len()).unwrap_or(PAGE);
        if let Some(found) = page.into_iter().find(|u| u.alias == alias) {
            return Ok(Some(found));
        }
        if count < PAGE {
            return Ok(None);
        }
        skip += PAGE;
    }
    Ok(None)
}

/// Delete an upstream (its routes cascade-delete via FK).
pub async fn delete(
    gateway: &Arc<dyn ServiceGatewayClientV1>,
    ctx: &SecurityContext,
    upstream_id: &str,
) -> McpResult<()> {
    let id = uuid::Uuid::from_str(upstream_id)
        .map_err(|e| McpError::Protocol(format!("invalid upstream id '{upstream_id}': {e}")))?;
    gateway
        .delete_upstream(ctx.clone(), id)
        .await
        .map_err(|e| McpError::Transport(format!("delete_upstream failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_with_path() {
        let p = parse_mcp_url("https://mcp.example.com/mcp").unwrap();
        assert_eq!(p.scheme, Scheme::Https);
        assert_eq!(p.host, "mcp.example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.base_path, "/mcp");
    }

    #[test]
    fn parse_preserves_trailing_slash() {
        // A trailing slash must survive parsing so the transport targets
        // `/mcp/` and the upstream does not 307-redirect from `/mcp`.
        let p = parse_mcp_url("https://mcp.corp.example.com:501/mcp/").unwrap();
        assert_eq!(p.base_path, "/mcp/");
    }

    #[test]
    fn parse_root_path_collapses_to_empty() {
        let p = parse_mcp_url("https://mcp.example.com/").unwrap();
        assert_eq!(p.base_path, "");
    }

    #[test]
    fn parse_http_with_port_no_path() {
        let p = parse_mcp_url("http://localhost:8080").unwrap();
        assert_eq!(p.scheme, Scheme::Http);
        assert_eq!(p.host, "localhost");
        assert_eq!(p.port, 8080);
        assert_eq!(p.base_path, "");
    }

    #[test]
    fn parse_rejects_bad_scheme() {
        assert!(parse_mcp_url("ftp://x/y").is_err());
        assert!(parse_mcp_url("not a url").is_err());
    }

    #[test]
    fn alias_is_deterministic() {
        assert_eq!(alias_for("abc"), "mcp-abc");
    }

    #[test]
    fn auth_mapping_none() {
        let c = auth_config_for(&McpAuth::None, "srv1", "https://mcp.example.com/mcp");
        assert_eq!(c.plugin_type, PLUGIN_NOOP);
        assert!(c.config.is_none());
    }

    #[test]
    fn auth_mapping_bearer() {
        let c = auth_config_for(
            &McpAuth::Bearer {
                secret_ref: "cred://tok".into(),
            },
            "srv1",
            "https://mcp.example.com/mcp",
        );
        assert_eq!(c.plugin_type, PLUGIN_APIKEY);
        let cfg = c.config.unwrap();
        assert_eq!(cfg["header"], "authorization");
        assert_eq!(cfg["prefix"], "Bearer ");
        assert_eq!(cfg["secret_ref"], "cred://tok");
    }

    #[test]
    fn auth_mapping_apikey() {
        let c = auth_config_for(
            &McpAuth::ApiKey {
                header: "x-api-key".into(),
                secret_ref: "cred://k".into(),
            },
            "srv1",
            "https://mcp.example.com/mcp",
        );
        assert_eq!(c.plugin_type, PLUGIN_APIKEY);
        let cfg = c.config.unwrap();
        assert_eq!(cfg["header"], "x-api-key");
        assert_eq!(cfg["prefix"], "");
    }

    #[test]
    fn auth_mapping_oauth2_joins_scopes() {
        let c = auth_config_for(
            &McpAuth::OAuth2 {
                client_id_ref: "cred://id".into(),
                client_secret_ref: "cred://sec".into(),
                token_url: "https://auth/token".into(),
                scopes: vec!["a".into(), "b".into()],
            },
            "srv1",
            "https://mcp.example.com/mcp",
        );
        assert_eq!(c.plugin_type, PLUGIN_OAUTH2);
        let cfg = c.config.unwrap();
        assert_eq!(cfg["token_endpoint"], "https://auth/token");
        assert_eq!(cfg["scopes"], "a b");
    }

    #[test]
    fn auth_mapping_oauth2_authorization_code() {
        let c = auth_config_for(
            &McpAuth::OAuth2AuthorizationCode {
                scopes: vec!["openid".into(), "mcp".into()],
            },
            "srv1",
            "https://mcp.example.com/mcp",
        );
        assert_eq!(c.plugin_type, PLUGIN_OAUTH2_AUTH_CODE);
        let cfg = c.config.unwrap();
        assert_eq!(cfg["token_ref"], "mcp_oauth_srv1");
        assert_eq!(cfg["resource"], "https://mcp.example.com/mcp");
        assert_eq!(cfg["scopes"], "openid mcp");
    }

    #[test]
    fn headers_config_allowlists_mcp_headers() {
        let h = mcp_headers_config();
        let req = h.request.unwrap();
        assert_eq!(req.passthrough, PassthroughMode::Allowlist);
        assert!(req.passthrough_allowlist.contains(&HEADER_MCP_SESSION_ID.to_owned()));
        assert!(req.passthrough_allowlist.contains(&HEADER_OAGW_TARGET_HOST.to_owned()));
        // Accept must be forwarded or MCP Streamable HTTP servers return 406.
        assert!(req.passthrough_allowlist.contains(&http::header::ACCEPT.as_str().to_owned()));
    }
}
