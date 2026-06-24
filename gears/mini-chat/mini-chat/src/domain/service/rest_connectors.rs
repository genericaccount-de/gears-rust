//! REST connector registry — config-derived tool catalog + request builder.
//!
//! Each configured connector (service name, host, method, path/query/body
//! templates, static auth) is surfaced to the model as its own dedicated
//! function tool (e.g. `search_confluence`). The model selects a tool purely
//! from its `name` + `description` + JSON-schema `parameters`; host/path/auth
//! knowledge lives here in config and is never exposed to the model.
//!
//! This module is pure (no network, no async). Transport is delegated to the
//! [`RestClient`](crate::domain::ports::RestClient) port.

use std::collections::HashMap;

use crate::config::{ParamIn, RestAPIConnector, RestAPIToolConfig, RestMethod as CfgRestMethod};
use crate::domain::llm::LlmTool;
use crate::domain::ports::rest_client::{RestMethod, RestRequest};

/// Error building a connector request from model-supplied input. Surfaced to
/// the model as a graceful `function_call_output` (never fails the turn).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    /// No connector registered under this tool name.
    UnknownTool(String),
    /// A required parameter was missing from the model input.
    MissingRequired { tool: String, param: String },
    /// The assembled URL was invalid.
    InvalidUrl { tool: String, detail: String },
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTool(name) => write!(f, "unknown connector tool '{name}'"),
            Self::MissingRequired { tool, param } => {
                write!(f, "connector '{tool}': missing required parameter '{param}'")
            }
            Self::InvalidUrl { tool, detail } => {
                write!(f, "connector '{tool}': could not build URL: {detail}")
            }
        }
    }
}

impl std::error::Error for ConnectorError {}

/// Config-derived registry of REST connectors.
///
/// Holds the connectors keyed by `tool_name` and a precomputed `Vec<LlmTool>`
/// for context assembly. Host allowlisting is enforced by the transport adapter
/// ([`ReqwestRestClient`](crate::infra::rest::reqwest_rest_client::ReqwestRestClient)),
/// not here, since this module is pure.
#[derive(Debug, Clone)]
pub struct RestAPIConnectorRegistry {
    connectors: HashMap<String, RestAPIConnector>,
    tools: Vec<LlmTool>,
}

impl RestAPIConnectorRegistry {
    /// Build a registry from validated config. Connectors with an unparseable
    /// `base_url` are skipped (config `validate()` already rejects these, but
    /// the constructor stays defensive).
    #[must_use]
    pub fn new(cfg: &RestAPIToolConfig) -> Self {
        let mut connectors = HashMap::new();
        let mut tools = Vec::new();

        for c in &cfg.connectors {
            tools.push(LlmTool::Function {
                name: c.tool_name.clone(),
                description: c.description.clone(),
                parameters: build_schema(c),
            });
            connectors.insert(c.tool_name.clone(), c.clone());
        }

        Self { connectors, tools }
    }

    /// The function-tool list to append during context assembly.
    #[must_use]
    pub fn tools(&self) -> &[LlmTool] {
        &self.tools
    }

    /// Whether a tool name maps to a registered connector.
    #[must_use]
    pub fn contains(&self, tool_name: &str) -> bool {
        self.connectors.contains_key(tool_name)
    }

    /// Build a fully-formed [`RestRequest`] for the given tool from the model's
    /// input arguments. The returned URL already includes the query string.
    ///
    /// # Errors
    /// Returns [`ConnectorError`] when the tool is unknown, a required param is
    /// missing, or the assembled URL is invalid.
    pub fn build_request(
        &self,
        tool_name: &str,
        input: &serde_json::Value,
    ) -> Result<RestRequest, ConnectorError> {
        let c = self
            .connectors
            .get(tool_name)
            .ok_or_else(|| ConnectorError::UnknownTool(tool_name.to_owned()))?;

        // Validate required params first.
        for p in &c.params {
            if p.required && value_for(input, &p.name).is_none() {
                return Err(ConnectorError::MissingRequired {
                    tool: tool_name.to_owned(),
                    param: p.name.clone(),
                });
            }
        }

        // Substitute path placeholders.
        let mut path = c.path.clone();
        for p in c.params.iter().filter(|p| p.location == ParamIn::Path) {
            let wire = p.wire_name.as_deref().unwrap_or(&p.name);
            if let Some(raw) = value_for(input, &p.name) {
                let v = apply_template(p.value_template.as_deref(), &raw);
                path = path.replace(&format!("{{{wire}}}"), &urlencoding::encode(&v));
            }
        }

        // Build base URL + path.
        let base = c.base_url.trim_end_matches('/');
        let mut url = url::Url::parse(&format!("{base}{path}")).map_err(|e| {
            ConnectorError::InvalidUrl {
                tool: tool_name.to_owned(),
                detail: e.to_string(),
            }
        })?;

        // Query params.
        let mut query: Vec<(String, String)> = Vec::new();
        for p in c.params.iter().filter(|p| p.location == ParamIn::Query) {
            let wire = p.wire_name.as_deref().unwrap_or(&p.name).to_owned();
            if let Some(raw) = value_for(input, &p.name) {
                query.push((wire, apply_template(p.value_template.as_deref(), &raw)));
            }
        }
        if !query.is_empty() {
            let mut qp = url.query_pairs_mut();
            for (k, v) in &query {
                qp.append_pair(k, v);
            }
        }

        // JSON body params (POST only).
        let body = if c.method == CfgRestMethod::Post {
            let mut obj = serde_json::Map::new();
            for p in c.params.iter().filter(|p| p.location == ParamIn::Body) {
                let wire = p.wire_name.as_deref().unwrap_or(&p.name).to_owned();
                if let Some(val) = input.get(&p.name) {
                    let templated = p.value_template.as_deref().map_or_else(
                        || val.clone(),
                        |t| {
                            serde_json::Value::String(apply_template(
                                Some(t),
                                &value_to_string(val),
                            ))
                        },
                    );
                    obj.insert(wire, templated);
                }
            }
            (!obj.is_empty()).then_some(serde_json::Value::Object(obj))
        } else {
            None
        };

        // Static headers + auth (auth applied last so it cannot be dropped).
        // Entries whose value is empty or a bare auth scheme are skipped so an
        // optional, unset `${VAR:-}` credential yields no header rather than a
        // malformed one (e.g. `Authorization: Bearer `).
        let mut headers: Vec<(String, String)> = c
            .headers
            .iter()
            .filter(|(_, v)| header_value_is_meaningful(v))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if let Some(auth) = &c.auth {
            for (k, v) in auth {
                if header_value_is_meaningful(v) {
                    headers.push((k.clone(), v.clone()));
                }
            }
        }

        Ok(RestRequest {
            method: map_method(c.method),
            url: url.to_string(),
            query,
            headers,
            body,
        })
    }
}

/// Whether a static header/auth value carries real content.
///
/// Returns `false` for values that are empty/whitespace or that consist solely
/// of an auth scheme keyword with no credential following it (e.g. `Bearer`
/// once an unset `${TOKEN:-}` expands to nothing). This makes credential
/// variables optional: a missing env var simply omits the header.
fn header_value_is_meaningful(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    !matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "bearer" | "basic" | "token" | "digest"
    )
}

/// Map the config-layer method enum to the domain-port enum.
fn map_method(m: CfgRestMethod) -> RestMethod {
    match m {
        CfgRestMethod::Get => RestMethod::Get,
        CfgRestMethod::Post => RestMethod::Post,
    }
}

/// Build the JSON schema (`parameters`) surfaced to the model for a connector.
fn build_schema(c: &RestAPIConnector) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required: Vec<serde_json::Value> = Vec::new();
    for p in &c.params {
        properties.insert(
            p.name.clone(),
            serde_json::json!({
                "type": p.r#type,
                "description": p.description,
            }),
        );
        if p.required {
            required.push(serde_json::Value::String(p.name.clone()));
        }
    }
    serde_json::json!({
        "type": "object",
        "properties": serde_json::Value::Object(properties),
        "required": serde_json::Value::Array(required),
    })
}

/// Look up a model-supplied parameter as a string (non-empty for strings).
fn value_for(input: &serde_json::Value, name: &str) -> Option<String> {
    let v = input.get(name)?;
    if v.is_null() {
        return None;
    }
    let s = value_to_string(v);
    if s.is_empty() { None } else { Some(s) }
}

/// Render a JSON scalar to a plain string (objects/arrays via compact JSON).
fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Apply an optional `value_template`, replacing the literal `{value}` token.
fn apply_template(template: Option<&str>, value: &str) -> String {
    match template {
        Some(t) => t.replace("{value}", value),
        None => value.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RestAPIConnector, RestParam};

    fn confluence_cfg() -> RestAPIToolConfig {
        RestAPIToolConfig {
            enabled: true,
            connectors: vec![RestAPIConnector {
                tool_name: "search_confluence".to_owned(),
                description: "Search Confluence.".to_owned(),
                method: CfgRestMethod::Get,
                base_url: "https://adn.acronis.com".to_owned(),
                path: "/wiki/rest/api/search".to_owned(),
                params: vec![RestParam {
                    name: "query".to_owned(),
                    location: ParamIn::Query,
                    required: true,
                    r#type: "string".to_owned(),
                    description: "What to search for.".to_owned(),
                    wire_name: Some("cql".to_owned()),
                    value_template: Some("text~\"{value}\"".to_owned()),
                }],
                headers: HashMap::from([("Accept".to_owned(), "application/json".to_owned())]),
                auth: Some(HashMap::from([(
                    "Authorization".to_owned(),
                    "Bearer t0ken".to_owned(),
                )])),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn registry_exposes_one_tool() {
        let reg = RestAPIConnectorRegistry::new(&confluence_cfg());
        assert_eq!(reg.tools().len(), 1);
        assert!(reg.contains("search_confluence"));
        assert!(!reg.contains("nope"));
    }

    #[test]
    fn build_request_confluence_url_with_template() {
        let reg = RestAPIConnectorRegistry::new(&confluence_cfg());
        let req = reg
            .build_request(
                "search_confluence",
                &serde_json::json!({"query": "datacenters list"}),
            )
            .unwrap();
        assert_eq!(req.method, RestMethod::Get);
        assert!(req.url.starts_with("https://adn.acronis.com/wiki/rest/api/search?cql="));
        // value_template wraps the value: text~"datacenters list" (url-encoded).
        assert!(req.url.contains("text"));
        assert!(req.url.contains("datacenters"));
        // Static headers + auth carried verbatim.
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Accept" && v == "application/json")
        );
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer t0ken")
        );
        assert!(req.body.is_none());
    }

    #[test]
    fn header_value_is_meaningful_filters_empty_and_bare_schemes() {
        assert!(header_value_is_meaningful("Bearer t0ken"));
        assert!(header_value_is_meaningful("application/json"));
        assert!(!header_value_is_meaningful(""));
        assert!(!header_value_is_meaningful("   "));
        // An unset `${TOKEN:-}` leaves a trailing space → bare scheme.
        assert!(!header_value_is_meaningful("Bearer "));
        assert!(!header_value_is_meaningful("basic"));
        assert!(!header_value_is_meaningful("Token"));
    }

    #[test]
    fn build_request_omits_auth_when_token_unset() {
        // Simulates a post-expansion `${CONFLUENCE_TOKEN:-}` that resolved empty.
        let mut cfg = confluence_cfg();
        cfg.connectors[0].auth = Some(HashMap::from([(
            "Authorization".to_owned(),
            "Bearer ".to_owned(),
        )]));
        // Also exercise an empty static header.
        cfg.connectors[0]
            .headers
            .insert("X-Optional".to_owned(), String::new());

        let reg = RestAPIConnectorRegistry::new(&cfg);
        let req = reg
            .build_request("search_confluence", &serde_json::json!({"query": "x"}))
            .unwrap();

        assert!(
            !req.headers.iter().any(|(k, _)| k == "Authorization"),
            "empty bearer auth must be dropped"
        );
        assert!(
            !req.headers.iter().any(|(k, _)| k == "X-Optional"),
            "empty static header must be dropped"
        );
        // Non-empty static header is still present.
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Accept" && v == "application/json")
        );
    }

    #[test]
    fn build_request_missing_required_param_errors() {
        let reg = RestAPIConnectorRegistry::new(&confluence_cfg());
        let err = reg
            .build_request("search_confluence", &serde_json::json!({}))
            .unwrap_err();
        assert_eq!(
            err,
            ConnectorError::MissingRequired {
                tool: "search_confluence".to_owned(),
                param: "query".to_owned(),
            }
        );
    }

    #[test]
    fn build_request_unknown_tool_errors() {
        let reg = RestAPIConnectorRegistry::new(&confluence_cfg());
        let err = reg
            .build_request("missing", &serde_json::json!({}))
            .unwrap_err();
        assert_eq!(err, ConnectorError::UnknownTool("missing".to_owned()));
    }

    #[test]
    fn build_request_substitutes_path_placeholder() {
        let cfg = RestAPIToolConfig {
            enabled: true,
            connectors: vec![RestAPIConnector {
                tool_name: "get_page".to_owned(),
                description: "Get a page.".to_owned(),
                method: CfgRestMethod::Get,
                base_url: "https://adn.acronis.com".to_owned(),
                path: "/wiki/rest/api/content/{id}".to_owned(),
                params: vec![RestParam {
                    name: "id".to_owned(),
                    location: ParamIn::Path,
                    required: true,
                    r#type: "string".to_owned(),
                    description: "Page id.".to_owned(),
                    wire_name: None,
                    value_template: None,
                }],
                headers: HashMap::new(),
                auth: None,
            }],
            ..Default::default()
        };
        let reg = RestAPIConnectorRegistry::new(&cfg);
        let req = reg
            .build_request("get_page", &serde_json::json!({"id": "12345"}))
            .unwrap();
        assert_eq!(req.url, "https://adn.acronis.com/wiki/rest/api/content/12345");
    }

    #[test]
    fn build_request_post_assembles_json_body() {
        let cfg = RestAPIToolConfig {
            enabled: true,
            connectors: vec![RestAPIConnector {
                tool_name: "create_item".to_owned(),
                description: "Create an item.".to_owned(),
                method: CfgRestMethod::Post,
                base_url: "https://adn.acronis.com".to_owned(),
                path: "/api/items".to_owned(),
                params: vec![RestParam {
                    name: "title".to_owned(),
                    location: ParamIn::Body,
                    required: true,
                    r#type: "string".to_owned(),
                    description: "Item title.".to_owned(),
                    wire_name: None,
                    value_template: None,
                }],
                headers: HashMap::new(),
                auth: None,
            }],
            ..Default::default()
        };
        let reg = RestAPIConnectorRegistry::new(&cfg);
        let req = reg
            .build_request("create_item", &serde_json::json!({"title": "hello"}))
            .unwrap();
        assert_eq!(req.method, RestMethod::Post);
        assert_eq!(req.body, Some(serde_json::json!({"title": "hello"})));
    }
}
