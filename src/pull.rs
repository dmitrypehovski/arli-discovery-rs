//! The room cannot dial this agent, so the agent calls the room and holds the poll open.
//!
//! Why this exists: most agents have no public address, and a room cannot dial through somebody else's router.
//! The direction of the first packet is reversible: the agent presents its signed card, signs the room's nonce,
//! hands over the profile it publishes itself, and receives a token and a queue. It then asks the room for the
//! next call, answers it from its own state, and posts the answer back. The exchange that travels this way is
//! the same exchange, with the same envelopes and the same witness rule; only the transport differs.
//!
//! What it does not claim: there is no address to test, so the proof of the key is the signature over the room's
//! nonce and nothing else, and the room records the reachability as outbound only rather than pretending an
//! address exists. The token has a term; when the room refuses it under its own name, this loop registers again.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::{dispatch, AgentState};

const RETRY_SECONDS: u64 = 3;
/// Our own agent signs one nonce per address and purpose per minute, so a registration repeated inside that
/// window is refused by the agent the loop is registering. Waiting is the fix; hammering it turns a delay into
/// a flood of refusals.
const RATE_WAIT_SECONDS: u64 = 61;
const POLL_TIMEOUT_SECONDS: u64 = 60;

fn locked(state: &Arc<Mutex<AgentState>>, method: &str, params: &Value) -> Result<Value, String> {
    let mut guard = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    dispatch(&mut guard, method, params).map_err(|(code, message)| format!("{}: {}", code, message))
}

fn post(room: &str, path: &str, body: &Value) -> Result<Value, String> {
    let url = format!("{}{}", room, path);
    let response = ureq::post(&url)
        .timeout(Duration::from_secs(POLL_TIMEOUT_SECONDS))
        .send_json(body.clone())
        .map_err(|error| format!("post {} failed: {}", url, error))?;
    response
        .into_json::<Value>()
        .map_err(|error| format!("post {} answered something that is not json: {}", url, error))
}

fn register(room: &str, state: &Arc<Mutex<AgentState>>, kind: &str, city: &str, headline: &str)
    -> Result<String, String>
{
    let card = {
        let guard = state.lock().map_err(|_| "state lock poisoned".to_string())?;
        guard.card.clone()
    };
    let hello = post(room, "/api/pull/hello", &json!({ "card": card }))?;
    let nonce = hello.get("nonce").cloned().unwrap_or(Value::Null);
    if nonce.is_null() {
        return Err(format!("the room did not issue a nonce: {}", hello));
    }
    let signed = locked(state, "arli/identity/sign",
                        &json!({ "nonce": nonce, "purpose": hello.get("purpose").cloned()
                            .unwrap_or(json!("pull")) }))?;
    let profile = locked(state, "arli/profile", &json!({}))?;
    let answer = post(room, "/api/pull/register", &json!({
        "card": card,
        "nonce": nonce,
        "signature": signed.get("signature").cloned().unwrap_or(json!("")),
        "kind": kind, "city": city, "headline": headline, "profile": profile,
    }))?;
    if answer.get("registered") != Some(&json!(true)) {
        return Err(format!("registration did not take: {}", answer));
    }
    println!("registered as {}: {}", answer.get("id").cloned().unwrap_or(json!("?")),
             answer.get("note").cloned().unwrap_or(json!("")));
    Ok(answer.get("pull_token").and_then(|value| value.as_str()).unwrap_or("").to_string())
}

/// Register once, then answer whatever the room asks through the poll, until the process is stopped.
pub fn run(room: &str, state: Arc<Mutex<AgentState>>, kind: String, city: String, headline: String) -> ! {
    loop {
        match register(room, &state, &kind, &city, &headline) {
            Err(error) => {
                let wait = if error.contains("rate_limited") { RATE_WAIT_SECONDS } else { RETRY_SECONDS };
                eprintln!("pull: {} (waiting {}s)", error, wait);
                std::thread::sleep(Duration::from_secs(wait));
                continue;
            }
            Ok(token) => {
                let url = format!("{}/api/pull?pull_token={}", room, token);
                loop {
                    let call = match ureq::get(&url).timeout(Duration::from_secs(POLL_TIMEOUT_SECONDS)).call() {
                        Ok(response) => response.into_json::<Value>().unwrap_or(json!(null)),
                        Err(ureq::Error::Status(403, _)) => {
                            println!("the room no longer knows this token: registering again");
                            break;
                        }
                        Err(error) => {
                            eprintln!("poll failed: {}", error);
                            std::thread::sleep(Duration::from_secs(RETRY_SECONDS));
                            continue;
                        }
                    };
                    let call_id = call.get("call_id").cloned().unwrap_or(json!(""));
                    let method = call.get("method").and_then(|value| value.as_str()).unwrap_or("").to_string();
                    if call_id.is_null() || call_id == json!("") || method.is_empty() {
                        continue;
                    }
                    let params = call.get("params").cloned().unwrap_or(json!({}));
                    let answer = match locked(&state, &method, &params) {
                        Ok(result) => json!({ "pull_token": token, "call_id": call_id, "result": result }),
                        // A refusal travels as a refusal, with its code, or the room reads a failure as silence.
                        Err(error) => json!({ "pull_token": token, "call_id": call_id, "error": error }),
                    };
                    match post(room, "/api/pull/answer", &answer) {
                        Ok(_) => println!("answered {}", method),
                        Err(error) => eprintln!("answer could not be delivered: {}", error),
                    }
                }
            }
        }
    }
}