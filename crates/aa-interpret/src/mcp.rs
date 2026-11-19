//! The report's tools as a server an outside agent can talk to.
//!
//! Speaks the Model Context Protocol over standard input and output: one JSON-RPC message per
//! line. It serves one report, answers only the read-only questions of [`crate::tools`], and
//! stops when its input closes.

use std::io::{BufRead, Write};

use aa_core::Report;
use serde_json::{Value, json};

use crate::Language;
use crate::tools::{Tools, specs};

/// The protocol revision this server was written against. A client that asks for another is
/// answered with this one, as the protocol prescribes.
const PROTOCOL: &str = "2025-06-18";

/// The reply to one message; `None` for a notification, which gets none.
fn reply(tools: &Tools, message: &Value) -> Option<Value> {
    let id = message.get("id").filter(|id| !id.is_null())?.clone();
    let method = message.get("method").and_then(Value::as_str).unwrap_or_default();
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "analyze-anything", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Read-only questions about one Analyze Anything report: its findings, their evidence, and the files of the analyzed input.",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({
            "tools": specs().iter().map(|spec| json!({
                "name": spec.name,
                "description": spec.description,
                "inputSchema": spec.schema,
                "annotations": { "readOnlyHint": true },
            })).collect::<Vec<_>>(),
        })),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
            let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            // A question that cannot be answered is a result the model reads, not a protocol error.
            Ok(match tools.call(name, &arguments) {
                Ok(answer) => json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&answer).unwrap_or_default() }] }),
                Err(problem) => json!({ "content": [{ "type": "text", "text": problem }], "isError": true }),
            })
        }
        other => Err(json!({ "code": -32601, "message": format!("method not found: {other}") })),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
    })
}

/// Serves `report` until `input` ends.
pub fn serve(report: &Report, language: Language, input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
    let tools = Tools::new(report, language);
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Value>(&line) {
            Ok(message) => reply(&tools, &message),
            Err(error) => {
                Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": format!("not JSON: {error}") } }))
            }
        };
        if let Some(answer) = answer {
            writeln!(output, "{answer}")?;
            output.flush()?;
        }
    }
    Ok(())
}
