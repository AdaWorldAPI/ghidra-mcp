//! The `/mcp/schema` contract — the Ghidra Java server self-describes, and
//! this crate turns that description into MCP tools at runtime.
//!
//! This is what makes the Rust bridge a **swap** rather than a rewrite. The
//! Java side is the fat half: ~251 tools, discovered from `@McpTool`
//! annotations, exposed as REST endpoints and enumerated at `/mcp/schema`.
//! The Python bridge hand-maintains no tool list — it fetches that schema
//! and registers each entry. So does this.
//!
//! Consequence worth stating: a new tool added on the Java side appears in
//! both bridges with **no change to either**. A Rust bridge that hard-coded
//! tools would have to chase the Java side forever and would not be a swap.
//!
//! Upstream shape (from `AnnotationScanner`):
//! ```json
//! {"tools": [{"path": "/decompile_function", "method": "POST",
//!             "description": "...", "category": "...",
//!             "params": [{"name": "address", "type": "string",
//!                         "required": true, "description": "..."}]}]}
//! ```

use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Deserialize)]
pub struct RawSchema {
    #[serde(default)]
    pub tools: Vec<RawTool>,
}

#[derive(Debug, Deserialize)]
pub struct RawTool {
    pub path: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub params: Vec<RawParam>,
}

fn default_method() -> String {
    "GET".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct RawParam {
    pub name: String,
    #[serde(default = "default_type")]
    pub r#type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

fn default_type() -> String {
    "string".to_owned()
}

/// One tool, resolved: the MCP-visible name, the JSON Schema an MCP client
/// validates against, and the HTTP call to make on the Java server.
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub endpoint: String,
    pub http_method: String,
    pub input_schema: Map<String, Value>,
}

/// MCP tool names must be stable identifiers. The Java side's endpoint
/// paths are not guaranteed to be, so the same sanitisation the Python
/// bridge applies is applied here — otherwise the two bridges would expose
/// DIFFERENT names for the same endpoint and would not be swappable.
fn sanitize(raw: &str) -> String {
    let s: String = raw
        .trim_start_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    s.trim_matches('_').to_owned()
}

/// Map the Java side's loose type vocabulary onto JSON Schema types.
///
/// `address` and `json` are Ghidra-side conveniences that are transported
/// as strings; `any` has no JSON Schema equivalent and degrades to string
/// rather than being omitted (an absent `type` would let a client send
/// anything, which is laxer than the Java side accepts).
fn json_type(t: &str) -> &'static str {
    match t {
        "integer" => "integer",
        "boolean" => "boolean",
        "number" => "number",
        "object" => "object",
        "array" => "array",
        _ => "string",
    }
}

/// Parse the upstream schema into tool definitions, de-duplicating names.
///
/// Collisions are resolved by suffixing `_2`, `_3`, … which matches the
/// Python bridge's `_allocate_tool_name`. A collision is not an error: two
/// distinct endpoints legitimately sanitize to the same identifier, and
/// dropping one would silently remove a capability.
pub fn parse(raw: RawSchema) -> Vec<ToolDef> {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(raw.tools.len());

    for t in raw.tools {
        let raw_name = t.name.clone().unwrap_or_else(|| t.path.clone());
        let base = sanitize(&raw_name);
        let base = if base.is_empty() {
            "tool".to_owned()
        } else {
            base
        };

        let mut name = base.clone();
        let mut n = 2usize;
        while !used.insert(name.clone()) {
            name = format!("{base}_{n}");
            n += 1;
        }

        let mut properties = Map::new();
        let mut required = Vec::new();
        for p in &t.params {
            let mut pd = Map::new();
            pd.insert("type".into(), Value::String(json_type(&p.r#type).into()));
            if let Some(d) = &p.description {
                if !d.is_empty() {
                    pd.insert("description".into(), Value::String(d.clone()));
                }
            }
            properties.insert(p.name.clone(), Value::Object(pd));
            if p.required {
                required.push(Value::String(p.name.clone()));
            }
        }

        let mut input_schema = Map::new();
        input_schema.insert("type".into(), Value::String("object".into()));
        input_schema.insert("properties".into(), Value::Object(properties));
        input_schema.insert("required".into(), Value::Array(required));

        out.push(ToolDef {
            name,
            description: t.description,
            endpoint: t.path,
            http_method: t.method,
            input_schema,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(json: &str) -> Vec<ToolDef> {
        parse(serde_json::from_str(json).expect("schema parses"))
    }

    #[test]
    fn a_tool_becomes_an_mcp_tool_with_a_json_schema() {
        let t = schema(
            r#"{"tools":[{"path":"/decompile_function","method":"POST",
                 "description":"Decompile","category":"function",
                 "params":[{"name":"address","type":"string","required":true,
                            "description":"Entry point"},
                           {"name":"timeout","type":"integer","required":false}]}]}"#,
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].name, "decompile_function");
        assert_eq!(t[0].endpoint, "/decompile_function");
        assert_eq!(t[0].http_method, "POST");

        let props = t[0].input_schema["properties"].as_object().unwrap();
        assert_eq!(props["address"]["type"], "string");
        assert_eq!(props["address"]["description"], "Entry point");
        assert_eq!(props["timeout"]["type"], "integer");

        // Two-sided: required carries the required one and NOT the optional
        // one. A version that marked everything required would pass a
        // contains() check.
        let req = t[0].input_schema["required"].as_array().unwrap();
        assert!(req.contains(&Value::String("address".into())));
        assert!(!req.contains(&Value::String("timeout".into())));
    }

    /// Dropping a colliding tool would silently remove a Ghidra capability,
    /// so collisions must rename rather than discard.
    #[test]
    fn colliding_names_are_suffixed_not_dropped() {
        let t = schema(
            r#"{"tools":[{"path":"/get/thing","params":[]},
                         {"path":"/get_thing","params":[]}]}"#,
        );
        assert_eq!(t.len(), 2, "neither tool may be dropped");
        assert_eq!(t[0].name, "get_thing");
        assert_eq!(t[1].name, "get_thing_2");
        // Both must still address their OWN endpoint — the rename is
        // cosmetic and must not rewrite where the call goes.
        assert_eq!(t[0].endpoint, "/get/thing");
        assert_eq!(t[1].endpoint, "/get_thing");
    }

    #[test]
    fn method_defaults_to_get_and_missing_params_are_an_empty_object() {
        let t = schema(r#"{"tools":[{"path":"/check_connection"}]}"#);
        assert_eq!(t[0].http_method, "GET");
        assert!(t[0].input_schema["properties"]
            .as_object()
            .unwrap()
            .is_empty());
        assert!(t[0].input_schema["required"].as_array().unwrap().is_empty());
    }

    /// `any` has no JSON Schema type. Degrading to `string` is deliberate:
    /// omitting `type` entirely would let a client send anything, which is
    /// laxer than the Java side accepts.
    #[test]
    fn unknown_types_degrade_to_string_rather_than_being_omitted() {
        let t = schema(
            r#"{"tools":[{"path":"/x","params":[
                 {"name":"a","type":"any"},{"name":"b","type":"address"}]}]}"#,
        );
        let props = t[0].input_schema["properties"].as_object().unwrap();
        assert_eq!(props["a"]["type"], "string");
        assert_eq!(props["b"]["type"], "string");
    }

    #[test]
    fn an_empty_schema_is_not_an_error() {
        assert!(schema(r#"{"tools":[]}"#).is_empty());
        assert!(schema(r#"{}"#).is_empty());
    }
}
