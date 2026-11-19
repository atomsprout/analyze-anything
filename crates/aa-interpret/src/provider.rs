//! The two API protocols: a conversation with tools, as each service wants it written.
//!
//! [`Chat`] keeps the conversation in the service's own shape, builds each request and reads
//! each reply. All of it is plain functions over JSON, tested without a network; [`Net`] is the
//! one place that talks to a server.

use std::time::Duration;

use serde_json::{Value, json};

use crate::config::{Api, Provider};
use crate::tools::Spec;

/// Version of Anthropic's API this program speaks.
const ANTHROPIC_VERSION: &str = "2026-10-21";
/// Room for the model's reasoning and its answer in one reply.
const ANTHROPIC_MAX_TOKENS: u32 = 16000;

/// One HTTP POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Something that can carry a request to a server and bring back the status and body.
pub trait Transport {
    fn post(&self, request: &HttpRequest, timeout: Duration) -> Result<(u16, String), String>;
}

/// A question the model asks of the report.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub id: String,
    pub name: String,
    /// The arguments; `Null` when the model wrote something that is not JSON.
    pub input: Value,
}

/// One reply of the model: questions to answer, or its final text.
#[derive(Debug, Clone, PartialEq)]
pub struct Turn {
    pub text: String,
    pub calls: Vec<Call>,
    /// The model that answered, as the service names it.
    pub model: String,
    /// The reply as the service wants it repeated back in the conversation.
    echo: Value,
}

/// A conversation with one model service.
pub struct Chat {
    provider: Provider,
    system: String,
    messages: Vec<Value>,
}

impl Chat {
    pub fn new(provider: Provider, system: &str, user: &str) -> Self {
        Chat { provider, system: system.to_string(), messages: vec![json!({ "role": "user", "content": user })] }
    }

    /// The request for the model's next reply. With `tools`, the model may ask questions.
    pub fn request(&self, api: &Api, tools: Option<&[Spec]>) -> HttpRequest {
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        let (url, body) = match self.provider {
            Provider::Anthropic => {
                if let Some(key) = &api.key {
                    headers.push(("x-api-key".to_string(), key.clone()));
                }
                headers.push(("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()));
                let mut body =
                    json!({ "model": api.model, "max_tokens": ANTHROPIC_MAX_TOKENS, "system": self.system, "messages": self.messages });
                if let Some(tools) = tools {
                    body["tools"] = tools
                        .iter()
                        .map(|tool| json!({ "name": tool.name, "description": tool.description, "input_schema": tool.schema }))
                        .collect();
                }
                (format!("{}/v1/messages", api.base_url), body)
            }
            Provider::OpenaiCompatible => {
                if let Some(key) = &api.key {
                    headers.push(("authorization".to_string(), format!("Bearer {key}")));
                }
                let mut messages = vec![json!({ "role": "system", "content": self.system })];
                messages.extend(self.messages.iter().cloned());
                // Only what every such service accepts: no token limit, temperature or response
                // format, whose names and support differ from one service to the next.
                let mut body = json!({ "model": api.model, "messages": messages });
                if let Some(tools) = tools {
                    body["tools"] = tools
                        .iter()
                        .map(|tool| json!({ "type": "function", "function": { "name": tool.name, "description": tool.description, "parameters": tool.schema } }))
                        .collect();
                }
                (format!("{}/chat/completions", api.base_url), body)
            }
        };
        HttpRequest { url, headers, body: body.to_string() }
    }

    /// Reads the service's reply to [`Chat::request`].
    pub fn read(&self, status: u16, body: &str) -> Result<Turn, String> {
        if !(200..300).contains(&status) {
            let hint = match status {
                401 | 403 => " (is the API key right?)",
                402 => " (the account has no balance or credit)",
                404 => " (are the address and the model name right?)",
                429 => " (rate limit or quota; try again later)",
                _ => "",
            };
            return Err(format!("the service answered {status}{hint}: {}", error_text(body)));
        }
        let reply: Value = serde_json::from_str(body).map_err(|error| format!("the service's answer is not JSON: {error}"))?;
        let model = reply.get("model").and_then(Value::as_str).unwrap_or_default().to_string();
        let text_of = |value: Option<&Value>| value.and_then(Value::as_str).unwrap_or_default().to_string();
        match self.provider {
            Provider::Anthropic => {
                match reply.get("stop_reason").and_then(Value::as_str) {
                    Some("refusal") => return Err("the model declined to answer".into()),
                    Some("max_tokens") => return Err("the model's answer was cut off at the token limit".into()),
                    _ => {}
                }
                let blocks = reply.get("content").and_then(Value::as_array).ok_or("the service's answer has no content")?;
                let kind = |block: &Value, kind: &str| block.get("type").and_then(Value::as_str) == Some(kind);
                // Thinking blocks come first; the answer is the text blocks.
                let text = blocks.iter().filter(|block| kind(block, "text")).map(|block| text_of(block.get("text"))).collect::<String>();
                let calls = blocks
                    .iter()
                    .filter(|block| kind(block, "tool_use"))
                    .map(|block| Call {
                        id: text_of(block.get("id")),
                        name: text_of(block.get("name")),
                        input: block.get("input").cloned().unwrap_or(Value::Null),
                    })
                    .collect();
                // Every block goes back unchanged, thinking included: the service checks them.
                Ok(Turn { text, calls, model, echo: json!({ "role": "assistant", "content": blocks }) })
            }
            Provider::OpenaiCompatible => {
                let choice = reply.get("choices").and_then(|choices| choices.get(0)).ok_or("the service's answer has no choices")?;
                if choice.get("finish_reason").and_then(Value::as_str) == Some("length") {
                    return Err("the model's answer was cut off at the token limit".into());
                }
                let message = choice.get("message").ok_or("the service's answer has no message")?;
                if let Some(refusal) = message.get("refusal").and_then(Value::as_str) {
                    return Err(format!("the model declined to answer: {refusal}"));
                }
                let calls = message
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .map(|calls| {
                        calls
                            .iter()
                            .map(|call| {
                                let function = call.get("function");
                                let arguments = function.and_then(|f| f.get("arguments")).and_then(Value::as_str).unwrap_or("{}");
                                let arguments = if arguments.trim().is_empty() { "{}" } else { arguments };
                                Call {
                                    id: text_of(call.get("id")),
                                    name: text_of(function.and_then(|f| f.get("name"))),
                                    input: serde_json::from_str(arguments).unwrap_or(Value::Null),
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(Turn { text: text_of(message.get("content")), calls, model, echo: message.clone() })
            }
        }
    }

    /// Adds the model's reply and the answers to its questions, in the order they were asked.
    /// `note` is said to the model along with them.
    pub fn answer(&mut self, turn: &Turn, answers: &[String], note: Option<&str>) {
        self.messages.push(turn.echo.clone());
        match self.provider {
            Provider::Anthropic => {
                let mut content: Vec<Value> = turn
                    .calls
                    .iter()
                    .zip(answers)
                    .map(|(call, answer)| json!({ "type": "tool_result", "tool_use_id": call.id, "content": answer }))
                    .collect();
                if let Some(note) = note {
                    content.push(json!({ "type": "text", "text": note }));
                }
                if !content.is_empty() {
                    self.messages.push(json!({ "role": "user", "content": content }));
                }
            }
            Provider::OpenaiCompatible => {
                for (call, answer) in turn.calls.iter().zip(answers) {
                    self.messages.push(json!({ "role": "tool", "tool_call_id": call.id, "content": answer }));
                }
                if let Some(note) = note {
                    self.messages.push(json!({ "role": "user", "content": note }));
                }
            }
        }
    }
}

/// The message of an error body, in either protocol's shape; else the start of the body.
fn error_text(body: &str) -> String {
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let message = parsed.as_ref().and_then(|value| {
        let error = value.get("error")?;
        error.get("message").and_then(Value::as_str).or_else(|| error.as_str())
    });
    match message {
        Some(message) => message.to_string(),
        None => body.chars().take(300).collect(),
    }
}

/// The network.
pub struct Net;

impl Transport for Net {
    fn post(&self, request: &HttpRequest, timeout: Duration) -> Result<(u16, String), String> {
        // A status such as 401 is an answer with a body worth reading, not a transport failure.
        let config = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(timeout)).build();
        let agent = ureq::Agent::new_with_config(config);
        let mut call = agent.post(&request.url);
        for (name, value) in &request.headers {
            call = call.header(name, value);
        }
        let mut response = call.send(request.body.as_str()).map_err(|error| format!("cannot reach {}: {error}", request.url))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(16 * 1024 * 1024)
            .read_to_string()
            .map_err(|error| format!("cannot read the answer from {}: {error}", request.url))?;
        Ok((status, body))
    }
}
