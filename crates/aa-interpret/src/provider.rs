//! The two protocols: what a request looks like and how an answer is read.
//!
//! Building a request and reading an answer are plain functions over text, so they are tested
//! without a network. [`Net`] is the one place that talks to a server.

use std::time::Duration;

use serde_json::{Value, json};

use crate::config::{Provider, Settings};

/// Version of Anthropic's API this program speaks.
const ANTHROPIC_VERSION: &str = "2026-10-21";
/// Room for the model's reasoning and its answer.
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

/// What the model said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub text: String,
    /// The model that answered, as the service names it.
    pub model: String,
}

/// The shape the answer must have, for services that can hold a model to one.
fn answer_schema() -> Value {
    let statements = json!({
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "text": { "type": "string" },
                "cites": { "type": "array", "items": { "type": "string" } },
            },
            "required": ["text", "cites"],
            "additionalProperties": false,
        },
    });
    json!({
        "type": "object",
        "properties": { "summary": statements, "notable": statements, "next_steps": statements },
        "required": ["summary", "notable", "next_steps"],
        "additionalProperties": false,
    })
}

/// The request that asks `settings`' model. `key` is the API key, when there is one.
pub fn request(settings: &Settings, key: Option<&str>, system: &str, user: &str) -> HttpRequest {
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    let (url, body) = match settings.provider {
        Provider::Anthropic => {
            if let Some(key) = key {
                headers.push(("x-api-key".to_string(), key.to_string()));
            }
            headers.push(("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()));
            let body = json!({
                "model": settings.model,
                "max_tokens": ANTHROPIC_MAX_TOKENS,
                "system": system,
                "messages": [{ "role": "user", "content": user }],
                "output_config": { "format": { "type": "json_schema", "schema": answer_schema() } },
            });
            (format!("{}/v1/messages", settings.base_url), body)
        }
        Provider::OpenaiCompatible => {
            if let Some(key) = key {
                headers.push(("authorization".to_string(), format!("Bearer {key}")));
            }
            // Only what every such service accepts: no token limit, temperature or response
            // format, whose names and support differ from one service to the next.
            let body = json!({
                "model": settings.model,
                "messages": [{ "role": "system", "content": system }, { "role": "user", "content": user }],
            });
            (format!("{}/chat/completions", settings.base_url), body)
        }
    };
    HttpRequest { url, headers, body: body.to_string() }
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

/// Reads the service's reply to [`request`].
pub fn answer(provider: Provider, status: u16, body: &str) -> Result<Answer, String> {
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
    let text = match provider {
        Provider::Anthropic => {
            match reply.get("stop_reason").and_then(Value::as_str) {
                Some("refusal") => return Err("the model declined to answer".into()),
                Some("max_tokens") => return Err("the model's answer was cut off at the token limit".into()),
                _ => {}
            }
            // Thinking blocks come first; the answer is the text blocks.
            let blocks = reply.get("content").and_then(Value::as_array).ok_or("the service's answer has no content")?;
            blocks
                .iter()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<String>()
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
            message.get("content").and_then(Value::as_str).unwrap_or_default().to_string()
        }
    };
    if text.trim().is_empty() {
        return Err("the model answered with no text".into());
    }
    Ok(Answer { text, model })
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
