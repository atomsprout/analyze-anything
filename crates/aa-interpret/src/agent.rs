//! The `api` engine: this program runs the conversation itself.
//!
//! The model is shown a brief of the report and may ask questions of it, round after round,
//! through the tools of [`crate::tools`]. It ends when the model answers, or when it has had
//! its rounds and is told to.

use std::time::Duration;

use crate::config::Api;
use crate::provider::{Chat, Transport, Turn};
use crate::tools::{Tools, specs};

/// What a run of the loop produced.
pub struct Outcome {
    /// The model's final text.
    pub text: String,
    pub model: String,
    /// Replies the model gave, the last one included.
    pub turns: u32,
    /// Questions it asked of the report.
    pub lookups: u32,
}

/// What the loop needs from outside.
pub struct Run<'a> {
    pub api: &'a Api,
    pub transport: &'a dyn Transport,
    pub timeout: Duration,
    pub max_turns: u32,
    /// Told about each question as it is asked, for progress.
    pub on_step: &'a mut dyn FnMut(&str),
}

const ANSWER_NOW: &str = "You have looked up enough. Do not ask for anything more: give your answer now, as the JSON object described.";

pub fn run(run: Run, tools: &Tools, system: &str, user: &str) -> Result<Outcome, String> {
    let Run { api, transport, timeout, max_turns, on_step } = run;
    let offered = specs();
    let mut chat = Chat::new(api.provider, system, user);
    let mut lookups = 0;
    let mut turns = 0;
    loop {
        let request = chat.request(api, Some(offered.as_slice()));
        let (status, body) = transport.post(&request, timeout)?;
        // A model or service that knows nothing of tools refuses the first request; it can
        // still read the brief and answer from that.
        if turns == 0 && matches!(status, 400 | 404 | 422) {
            let refused = chat.read(status, &body).err().unwrap_or_default();
            let (status, body) = transport.post(&chat.request(api, None), timeout)?;
            if (200..300).contains(&status) {
                on_step("the model cannot look things up; it answers from the brief alone");
                let turn = chat.read(status, &body)?;
                return Ok(Outcome { text: turn.text, model: turn.model, turns: 1, lookups: 0 });
            }
            return Err(refused);
        }
        let turn: Turn = chat.read(status, &body)?;
        turns += 1;
        if turn.calls.is_empty() {
            if turn.text.trim().is_empty() {
                return Err("the model answered with no text".into());
            }
            return Ok(Outcome { text: turn.text, model: turn.model, turns, lookups });
        }
        if turns > max_turns {
            return Err(format!("the model kept asking questions and gave no answer in {max_turns} rounds"));
        }
        let answers: Vec<String> = turn
            .calls
            .iter()
            .map(|call| {
                lookups += 1;
                on_step(&format!("{} {}", call.name, call.input));
                match tools.call(&call.name, &call.input) {
                    Ok(answer) => answer.to_string(),
                    Err(problem) => format!("error: {problem}"),
                }
            })
            .collect();
        // The last round it may ask in: say so along with the answers.
        chat.answer(&turn, &answers, (turns == max_turns).then_some(ANSWER_NOW));
    }
}
