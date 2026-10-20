//! Second implementation of the ARLI Discovery Extension.
//!
//! Why it exists. The Python engine is the readable reference. This one answers the question a
//! standard lives or dies on: can somebody else implement the text from the text? So the lists
//! and the rules here were written from the normative document, and the conformance suite is the
//! judge. Where the two implementations disagree, the disagreement is the interesting part.
//!
//! What is finished and what is not is stated in the capability document rather than implied:
//! every method that is not finished yet refuses with the code `not_implemented`.

mod canon;
mod caps;
mod card;
mod lists;
mod psi;
mod state;

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Method, Response, Server};

use canon::canonical;
use lists::*;
use state::{Claim, Claims, Registry, Retention};

pub struct AgentState {
    pub name: String,
    pub features: Vec<String>,
    pub psi_holder: HashMap<String, psi::RsaKey>,
    pub psi_applicant: HashMap<String, (Vec<String>, Vec<num_bigint::BigUint>)>,
    pub signer: card::Signer1,
    pub card: Value,
    pub registry: Registry,
    pub retention: Retention,
    pub claims: Claims,
    pub negotiations: HashMap<String, Negotiation>,
}

#[derive(Clone, Default)]
pub struct Negotiation {
    pub seats: Vec<String>,
    pub turns: Vec<(String, String)>,
    pub settled: bool,
    pub closed: bool,
}

type Shared = Arc<Mutex<AgentState>>;

fn now_utc() -> String {
    // Seconds since the epoch, formatted as the text requires: a moment, not a wall clock style.
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{}", seconds)
}

/// The identifier must recompute from the envelope body, and the body is the nine fields the
/// text names, without the identifier itself and without the signature.
fn evidence_id(fields: &Value) -> String {
    let digest = Sha256::digest(canonical(fields).as_bytes());
    format!("ev_{}", hex::encode(digest))
}

fn envelope(
    signer: &card::Signer1,
    operation: &str,
    parameters: Value,
    normalized_result: Value,
    limitations: Vec<&str>,
) -> Value {
    let mut body = json!({
        "provider": {"id": "arli-rs", "name": "ARLI second implementation", "version": "0.1.0"},
        "operation": operation,
        "parameters": parameters,
        "normalized_result": normalized_result,
        "confidence": "observed",
        "authority": "local-calculation",
        "limitations": limitations,
        // The completeness block carries the fields the text names, so a reader can tell what
        // was dropped and why. An empty block with invented field names is not the same thing.
        "completeness": {
            "status": "complete_within_window",
            "conditions": [],
            "policy_filtered_sections": [],
            "truncated_sections": [],
            "unavailable_sections": [],
            "excluded": [],
            "dropped_events": {}
        },
        "captured_at": now_utc(),
    });
    let id = evidence_id(&body);
    body["evidence_id"] = Value::String(id);
    // The signature covers the body with the identifier in it, and excludes the signature itself.
    let signature: Signature = signer.key.sign(canonical(&body).as_bytes());
    body["signature"] = json!({
        "alg": "ES256",
        "kid": signer.kid,
        "value": B64.encode(signature.to_bytes()),
    });
    body
}

fn refusal(code: &str, detail: &str) -> (String, String) {
    (code.to_string(), detail.to_string())
}

fn require(params: &Value, field: &str) -> Result<(), (String, String)> {
    match params.get(field) {
        Some(Value::Null) | None => Err(refusal("missing_field", &format!("{} is required", field))),
        _ => Ok(()),
    }
}

fn intent_level_strength(level: &str) -> Option<usize> {
    CLAIM_LEVELS.iter().position(|item| *item == level)
}

fn types_comparable(a: &str, b: &str) -> bool {
    matches!(
        (a, b),
        ("supply", "demand") | ("demand", "supply") | ("person", "person")
    )
}

fn decide_opening(a: &Value, b: &Value, network: &str, admits_synthetic: bool, required: Option<&str>) -> Option<&'static str> {
    let active = |intent: &Value| intent.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
    if !active(a) || !active(b) {
        return Some("intent_inactive");
    }
    let synthetic = |intent: &Value| {
        intent.get("provenance").and_then(|v| v.as_str()).unwrap_or("human") == "synthetic"
    };
    if !admits_synthetic && (synthetic(a) || synthetic(b)) {
        return Some("synthetic_not_admitted");
    }
    let owner = |intent: &Value| intent.get("owner").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if owner(a) == owner(b) {
        return Some("same_owner");
    }
    let id = |intent: &Value| intent.get("intent_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if id(a) == id(b) {
        return Some("same_intent");
    }
    let net = |intent: &Value| intent.get("network").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if net(a) != network || net(b) != network {
        return Some("network_mismatch");
    }
    let kind = |intent: &Value| intent.get("type").and_then(|v| v.as_str()).unwrap_or("person").to_string();
    if !types_comparable(&kind(a), &kind(b)) {
        return Some("types_not_comparable");
    }
    if let Some(level) = required {
        let needed = intent_level_strength(level).unwrap_or(0);
        let level_of = |intent: &Value| {
            intent_level_strength(intent.get("claim_level").and_then(|v| v.as_str()).unwrap_or("declared"))
                .unwrap_or(0)
        };
        if level_of(a).min(level_of(b)) < needed {
            return Some("below_required_level");
        }
    }
    None
}

fn dispatch(state: &mut AgentState, method: &str, params: &Value) -> Result<Value, (String, String)> {
    match method {
        "agent/card" => Ok(json!({"card": state.card})),
        "arli/capabilities" => Ok(caps::capability_document()),

        "arli/registry/status" => Ok(json!({"registry": state.registry.to_json()})),
        "arli/registry/register" => {
            require(params, "kid")?;
            require(params, "principal_id")?;
            require(params, "public_pem")?;
            let kid = params["kid"].as_str().unwrap_or_default();
            state
                .registry
                .register(kid, params["principal_id"].as_str().unwrap_or_default(), params["public_pem"].as_str().unwrap_or_default())
                .map_err(|(code, detail)| refusal(&code, &detail))?;
            let (valid, reasons) = state.registry.check(kid);
            Ok(json!({"key": {"kid": kid}, "valid": valid, "reasons": reasons}))
        }
        "arli/registry/rotate" => {
            for field in ["kid", "new_kid", "new_public_pem"] {
                require(params, field)?;
            }
            let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("rotated");
            state
                .registry
                .rotate(params["kid"].as_str().unwrap_or_default(), params["new_kid"].as_str().unwrap_or_default(), params["new_public_pem"].as_str().unwrap_or_default(), reason)
                .map_err(|(code, detail)| refusal(&code, &detail))?;
            let old_valid = state.registry.check(params["kid"].as_str().unwrap_or_default()).0;
            let new_valid = state.registry.check(params["new_kid"].as_str().unwrap_or_default()).0;
            Ok(json!({"old_valid": old_valid, "new_valid": new_valid, "principal_revoked": !state.registry.principals.is_empty()}))
        }
        "arli/registry/revoke" => {
            require(params, "reason")?;
            let reason = params["reason"].as_str().unwrap_or_default();
            if let Some(principal) = params.get("principal_id").and_then(|v| v.as_str()) {
                state.registry.revoke_principal(principal, reason).map_err(|(c, d)| refusal(&c, &d))?;
                Ok(json!({"principal_id": principal, "active": true}))
            } else if let Some(kid) = params.get("kid").and_then(|v| v.as_str()) {
                state.registry.revoke_key(kid, reason).map_err(|(c, d)| refusal(&c, &d))?;
                Ok(json!({"kid": kid, "revoked": true}))
            } else {
                Err(refusal("missing_field", "either kid or principal_id is required"))
            }
        }
        "arli/registry/confirm" => {
            require(params, "principal_id")?;
            let principal = params["principal_id"].as_str().unwrap_or_default();
            state.registry.confirm_principal(principal).map_err(|(c, d)| refusal(&c, &d))?;
            Ok(json!({"principal_id": principal, "active": false}))
        }
        "arli/registry/check" => {
            require(params, "kid")?;
            let kid = params["kid"].as_str().unwrap_or_default();
            let (valid, reasons) = state.registry.check(kid);
            Ok(json!({"kid": kid, "valid": valid, "reasons": reasons}))
        }

        "arli/retention/status" => Ok(json!({"retention": state.retention.to_json()})),
        "arli/retention/record" => {
            require(params, "evidence_id")?;
            require(params, "intent_id")?;
            state.retention.store(params["evidence_id"].as_str().unwrap_or_default(), params["intent_id"].as_str().unwrap_or_default());
            Ok(json!({"record": {"evidence_id": params["evidence_id"], "intent_id": params["intent_id"]}}))
        }
        "arli/retention/archive" => {
            require(params, "intent_id")?;
            let intent_id = params["intent_id"].as_str().unwrap_or_default();
            let touched = state.retention.archive_intent(intent_id).map_err(|(c, d)| refusal(&c, &d))?;
            let searchable: Vec<String> = state
                .retention
                .records
                .iter()
                .filter(|(_, record)| record.deleted_reason.is_none())
                .map(|(id, _)| id.clone())
                .collect();
            let evidence = envelope(
                &state.signer,
                "retention_archive",
                json!({"intent_id": intent_id}),
                json!({"marked_deleted": touched}),
                vec!["Retention covers envelope metadata only: raw features never reach the server."],
            );
            Ok(json!({"intent_id": intent_id, "marked_deleted": touched, "searchable": searchable, "evidence": evidence}))
        }
        "arli/retention/delete" => {
            require(params, "evidence_id")?;
            let evidence_id = params["evidence_id"].as_str().unwrap_or_default();
            state.retention.delete_envelope(evidence_id).map_err(|(c, d)| refusal(&c, &d))?;
            Ok(json!({"record": {"evidence_id": evidence_id, "deleted_reason": "owner_request"}}))
        }
        "arli/retention/purge" => {
            let removed = state.retention.purge();
            Ok(json!({"removed": removed, "retention_days": 30}))
        }

        "arli/claims/status" => Ok(json!({
            "claims": state.claims.to_json(),
            "levels": CLAIM_LEVELS.to_vec(),
            "states": CLAIM_STATES.to_vec(),
            "claim_rejections": CLAIM_REJECTIONS.to_vec(),
            "issuance": "This implementation relays and verifies statements made by others and issues none of its own."
        })),
        "arli/claims/issuers" => {
            require(params, "name")?;
            require(params, "public_pem")?;
            let name = params["name"].as_str().unwrap_or_default().to_string();
            state.claims.issuers.insert(name.clone(), params["public_pem"].as_str().unwrap_or_default().to_string());
            let mut issuers: Vec<String> = state.claims.issuers.keys().cloned().collect();
            issuers.sort();
            Ok(json!({"issuers": issuers}))
        }
        "arli/claims/declare" => {
            require(params, "feature")?;
            require(params, "level")?;
            let claim = Claim {
                feature: params["feature"].as_str().unwrap_or_default().to_string(),
                level: params["level"].as_str().unwrap_or_default().to_string(),
                issuer: params.get("issuer").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                issuer_evidence: params.get("issuer_evidence").cloned(),
                state: params.get("state").and_then(|v| v.as_str()).unwrap_or("active").to_string(),
            };
            let (verified, reasons) = state.claims.verify(&claim);
            let response = json!({
                "claim": {
                    "feature": claim.feature,
                    "level": claim.level,
                    "issuer": claim.issuer,
                    "state": claim.state,
                    "has_issuer_evidence": claim.issuer_evidence.is_some()
                },
                "verified": verified,
                "reasons": reasons
            });
            state.claims.declared.insert(claim.feature.clone(), claim);
            Ok(response)
        }

        "arli/psi/keys" => {
            require(params, "session_id")?;
            let session = params["session_id"].as_str().unwrap_or_default().to_string();
            let key = psi::RsaKey::generate();
            let response = json!({
                "scheme": "closed_blind_rsa",
                "feature_cap": FEATURE_CAP,
                "n": psi::to_hex(&key.n),
                "e": psi::to_hex(&key.e)
            });
            state.psi_holder.insert(session, key);
            Ok(response)
        }
        "arli/psi/commit" => {
            for field in ["session_id", "peer_name", "n", "e"] {
                require(params, field)?;
            }
            let session = params["session_id"].as_str().unwrap_or_default().to_string();
            let n = psi::from_hex(params["n"].as_str().unwrap_or_default());
            let e = psi::from_hex(params["e"].as_str().unwrap_or_default());
            if state.features.len() > FEATURE_CAP {
                return Err(refusal(
                    "too_many_features",
                    &format!("{} features, cap is {}", state.features.len(), FEATURE_CAP),
                ));
            }
            let mut blinded: Vec<String> = Vec::new();
            let mut factors = Vec::new();
            for feature in state.features.clone() {
                let hashed = psi::feature_hash(&feature, &n);
                let (value, factor) = psi::blind(&hashed, &e, &n);
                blinded.push(psi::to_hex(&value));
                factors.push(factor);
            }
            let count = blinded.len();
            state.psi_applicant.insert(session, (state.features.clone(), factors));
            Ok(json!({"blinded": blinded, "count": count}))
        }
        "arli/psi/sign" => {
            for field in ["session_id", "blinded"] {
                require(params, field)?;
            }
            let session = params["session_id"].as_str().unwrap_or_default().to_string();
            let values = params["blinded"].as_array().cloned().unwrap_or_default();
            if values.len() > FEATURE_CAP {
                return Err(refusal(
                    "too_many_features",
                    &format!("{} values, cap is {}", values.len(), FEATURE_CAP),
                ));
            }
            let key = match state.psi_holder.get(&session) {
                Some(key) => key,
                None => {
                    return Err(refusal(
                        "missing_pair_key",
                        "no holder key for this session",
                    ))
                }
            };
            let signed: Vec<String> = values
                .iter()
                .map(|value| {
                    let blinded = psi::from_hex(value.as_str().unwrap_or_default());
                    psi::to_hex(&psi::token(&blinded, &key.d, &key.n))
                })
                .collect();
            let holder_tokens: Vec<String> = state
                .features
                .iter()
                .map(|feature| {
                    let hashed = psi::feature_hash(feature, &key.n);
                    psi::to_hex(&psi::token(&hashed, &key.d, &key.n))
                })
                .collect();
            Ok(json!({"signed": signed, "holder_tokens": holder_tokens}))
        }
        "arli/psi/finish" => {
            for field in ["session_id", "signed"] {
                require(params, field)?;
            }
            let session = params["session_id"].as_str().unwrap_or_default().to_string();
            let floor = match params.get("floor_basis_points") {
                Some(value) => value.as_u64(),
                None => return Err(refusal("missing_floor", "floor_basis_points is required")),
            }
            .ok_or_else(|| refusal("invalid_floor", "floor_basis_points must be an integer"))?;
            if floor > 10_000 {
                return Err(refusal("invalid_floor", &format!("floor_basis_points={}", floor)));
            }
            let n = psi::from_hex(params.get("n").and_then(|v| v.as_str()).unwrap_or_default());
            let signed = params["signed"].as_array().cloned().unwrap_or_default();
            let (own, factors) = match state.psi_applicant.get(&session) {
                Some(entry) => entry.clone(),
                None => {
                    return Err(refusal(
                        "missing_pair_key",
                        "no pending blinding for this session",
                    ))
                }
            };
            if signed.len() != factors.len() {
                return Err(refusal(
                    "length_mismatch",
                    &format!("{} signatures for {} blinded values", signed.len(), factors.len()),
                ));
            }
            let holder_tokens: Vec<num_bigint::BigUint> = params
                .get("holder_tokens")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .map(|item| psi::from_hex(item.as_str().unwrap_or_default()))
                        .collect()
                })
                .unwrap_or_default();
            let mut matched: Vec<String> = Vec::new();
            for (index, value) in signed.iter().enumerate() {
                let unblinded = psi::unblind(
                    &psi::from_hex(value.as_str().unwrap_or_default()),
                    &factors[index],
                    &n,
                );
                if holder_tokens.iter().any(|token| *token == unblinded) {
                    matched.push(own[index].clone());
                }
            }
            let total = own.len().max(1);
            let basis = (matched.len() as u64 * 10_000) / total as u64;
            let passed = basis >= floor;
            let returned = if passed { matched.clone() } else { Vec::new() };
            let mut evidence = envelope(
                &state.signer,
                "match_closed_intersection",
                json!({
                    "scheme": "closed_blind_rsa",
                    "floor_basis_points": floor,
                    "passed_floor": passed,
                    "matched_feature_count": matched.len()
                }),
                json!({"matched_feature_count": returned.len()}),
                vec![
                    "Offline enumeration of the counterparty's features is closed by the scheme.",
                    "Online probing of a single guess is not closed; it is bounded by one exchange per session.",
                ],
            );
            if !passed {
                evidence["completeness"]["excluded"] = json!([{
                    "section": "matched features",
                    "reason": "below_the_declared_floor",
                    "count": matched.len()
                }]);
                evidence["completeness"]["status"] = Value::String("policy_filtered".to_string());
                evidence["completeness"]["policy_filtered_sections"] = json!(["matched features"]);
            }
            Ok(json!({
                "matched_features": returned,
                "overlap_basis_points": basis,
                "floor_basis_points": floor,
                "passed_floor": passed,
                "evidence": evidence
            }))
        }
        "arli/psi/record" => {
            for field in ["session_id", "matched"] {
                require(params, field)?;
            }
            let floor = match params.get("floor_basis_points") {
                Some(value) => value.as_u64(),
                None => return Err(refusal("missing_floor", "floor_basis_points is required")),
            }
            .ok_or_else(|| refusal("invalid_floor", "floor_basis_points must be an integer"))?;
            if floor > 10_000 {
                return Err(refusal("invalid_floor", &format!("floor_basis_points={}", floor)));
            }
            let matched = params["matched"].as_array().cloned().unwrap_or_default();
            let evidence = envelope(
                &state.signer,
                "match_recorded",
                json!({"floor_basis_points": floor, "matched_feature_count": matched.len()}),
                json!({"matched_feature_count": matched.len()}),
                vec!["The holder records the same intersection; neither side learns the other's list."],
            );
            Ok(json!({
                "matched_features": matched,
                "floor_basis_points": floor,
                "evidence": evidence
            }))
        }
        "arli/negotiation/open" => {
            require(params, "negotiation_id")?;
            require(params, "peers")?;
            if let Some(intents) = params.get("intents").and_then(|v| v.as_array()) {
                if intents.len() == 2 {
                    let network = params.get("network").and_then(|v| v.as_str()).unwrap_or_default();
                    let admits_synthetic = params.get("admits_synthetic").and_then(|v| v.as_bool()).unwrap_or(false);
                    let required = params.get("required_level").and_then(|v| v.as_str());
                    if let Some(code) = decide_opening(&intents[0], &intents[1], network, admits_synthetic, required) {
                        let evidence = envelope(
                            &state.signer,
                            "negotiation_open",
                            json!({"negotiation_id": params["negotiation_id"], "rejection": code}),
                            json!({"opened": false}),
                            vec!["A refused pair is not ranked against other pairs; it is simply not opened."],
                        );
                        return Ok(json!({"opened": false, "rejection": code, "evidence": evidence}));
                    }
                }
            }
            let peers: Vec<String> = params["peers"]
                .as_array()
                .map(|items| items.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let negotiation_id = params["negotiation_id"].as_str().unwrap_or_default().to_string();
            let initiator = peers.first().cloned().unwrap_or_default();
            state.negotiations.insert(
                negotiation_id.clone(),
                Negotiation { seats: peers, turns: Vec::new(), settled: false, closed: false },
            );
            let evidence = envelope(
                &state.signer,
                "negotiation_open",
                json!({"negotiation_id": negotiation_id}),
                json!({"opened": true}),
                vec!["Eligibility is checked on declared standing, not on a live read of the network."],
            );
            Ok(json!({"opened": true, "initiator": initiator, "evidence": evidence}))
        }
        "arli/negotiation/turn" => {
            for field in ["negotiation_id", "seat", "action"] {
                require(params, field)?;
            }
            let negotiation_id = params["negotiation_id"].as_str().unwrap_or_default();
            let seat = params["seat"].as_str().unwrap_or_default().to_string();
            let action = params["action"].as_str().unwrap_or_default().to_string();
            let negotiation = match state.negotiations.get_mut(negotiation_id) {
                Some(negotiation) => negotiation,
                None => return Err(refusal("unknown_negotiation", &format!("unknown negotiation: {}", negotiation_id))),
            };
            if !contains(&ACTIONS, &action) {
                return Err(refusal("unknown_action", &action));
            }
            if negotiation.settled {
                return Err(refusal("already_settled", negotiation_id));
            }
            if !negotiation.seats.iter().any(|item| *item == seat) {
                return Err(refusal("not_a_seat", &format!("this agent holds seat {}, not {}", negotiation.seats.join(","), seat)));
            }
            if negotiation.turns.is_empty() {
                if action == "accept" || action == "counter" {
                    return Err(refusal("first_turn_is_propose_or_decline", "the initiator owes the first turn"));
                }
            } else {
                let last = negotiation.turns.last().map(|(s, _)| s.clone()).unwrap_or_default();
                if last == seat {
                    return Err(refusal("seats_must_alternate", "the same seat cannot take two turns in a row"));
                }
                if action == "accept" {
                    let last_action = negotiation.turns.last().map(|(_, a)| a.clone()).unwrap_or_default();
                    if last_action != "propose" {
                        return Err(refusal("accept_without_offer", "accept is legal only right after a propose"));
                    }
                    negotiation.settled = true;
                }
            }
            if negotiation.turns.len() as u32 >= MAX_TURNS {
                return Err(refusal("turn_limit", "the turn limit is reached; the negotiation stays unsettled"));
            }
            negotiation.turns.push((seat.clone(), action.clone()));
            let evidence = envelope(
                &state.signer,
                "negotiation_turn",
                json!({"negotiation_id": negotiation_id, "seat": seat, "action": action}),
                json!({"turns": negotiation.turns.len(), "settled": negotiation.settled}),
                vec!["The journal is shared by both seats; a turn is recorded once."],
            );
            Ok(json!({"accepted": true, "turns": negotiation.turns.len(), "settled": negotiation.settled, "evidence": evidence}))
        }
        "arli/opportunity/decide" => {
            require(params, "negotiation_id")?;
            require(params, "actor")?;
            require(params, "approve")?;
            let negotiation_id = params["negotiation_id"].as_str().unwrap_or_default();
            let negotiation = match state.negotiations.get(negotiation_id) {
                Some(negotiation) => negotiation,
                None => return Err(refusal("unknown_negotiation", &format!("unknown opportunity: {}", negotiation_id))),
            };
            if !negotiation.settled {
                return Err(refusal("not_settled", "humans decide only after the agents agreed"));
            }
            let actor = params["actor"].as_str().unwrap_or_default();
            if !negotiation.seats.iter().any(|item| *item == actor) {
                return Err(refusal("not_a_seat", actor));
            }
            Ok(json!({
                "opportunity_id": negotiation_id,
                "human_consent": params["approve"].as_bool().unwrap_or(false),
                "seats": negotiation.seats
            }))
        }

        // Not finished yet, and it says so with a code rather than pretending.
        _ => Err(refusal("not_implemented", &format!("{} is not implemented in this implementation yet", method))),
    }
}

fn json_response(value: &Value, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    Response::from_data(body)
        .with_status_code(status)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..]).unwrap())
}

fn handle(state: &Shared, request: tiny_http::Request) {
    let url = request.url().to_string();
    let method = request.method().clone();
    match (&method, url.as_str()) {
        (Method::Get, "/.well-known/agent-card.json") => {
            let card = state.lock().unwrap().card.clone();
            let _ = request.respond(json_response(&card, 200));
        }
        (Method::Get, "/.well-known/arli-capabilities.json") => {
            let _ = request.respond(json_response(&caps::capability_document(), 200));
        }
        (Method::Post, "/a2a/rpc") => {
            let mut body = String::new();
            let mut request = request;
            if request.as_reader().read_to_string(&mut body).is_err() {
                let _ = request.respond(json_response(&json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse_error: unreadable body"}}), 400));
                return;
            }
            let parsed: Result<Value, _> = serde_json::from_str(&body);
            let payload = match parsed {
                Ok(value) => value,
                Err(error) => {
                    let _ = request.respond(json_response(&json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("parse_error: {}", error)}}), 400));
                    return;
                }
            };
            let id = payload.get("id").cloned().unwrap_or(Value::Null);
            let method_name = payload.get("method").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let params = payload.get("params").cloned().unwrap_or(json!({}));
            if !contains(&METHOD_NAMES, &method_name) {
                let message = format!("unknown_method: {}", method_name);
                let _ = request.respond(json_response(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": message}}), 404));
                return;
            }
            let outcome = {
                let mut guard = state.lock().unwrap();
                dispatch(&mut guard, &method_name, &params)
            };
            let body = match outcome {
                Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                Err((code, detail)) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32602, "message": format!("{}: {}", code, detail)}
                }),
            };
            let _ = request.respond(json_response(&body, 200));
        }
        _ => {
            let _ = request.respond(json_response(&json!({"error": "not found", "path": url}), 404));
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut port = 8841u16;
    let mut name = "arli-rs-agent".to_string();
    let mut features: Vec<String> = vec![
        "skill:design".to_string(),
        "city:sf".to_string(),
        "role:founder".to_string(),
    ];
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--port" => {
                port = args.get(index + 1).and_then(|value| value.parse().ok()).unwrap_or(port);
                index += 2;
            }
            "--name" => {
                name = args.get(index + 1).cloned().unwrap_or(name);
                index += 2;
            }
            "--features" => {
                features = args
                    .get(index + 1)
                    .map(|value| value.split(',').map(|part| part.trim().to_string()).collect())
                    .unwrap_or(features);
                index += 2;
            }
            _ => index += 1,
        }
    }
    let signer = card::Signer1::random(&format!("{}-key-1", name));
    let base_url = format!("http://127.0.0.1:{}", port);
    let card = card::build_card(&signer, &name, &base_url);
    let state: Shared = Arc::new(Mutex::new(AgentState {
        name,
        features,
        psi_holder: HashMap::new(),
        psi_applicant: HashMap::new(),
        signer,
        card,
        registry: Registry::default(),
        retention: Retention::default(),
        claims: Claims::default(),
        negotiations: HashMap::new(),
    }));

    let address = format!("127.0.0.1:{}", port);
    let server = match Server::http(&address) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("cannot listen on {}: {}", address, error);
            std::process::exit(1);
        }
    };
    println!("arli-discovery-rs listening on http://{}", address);
    for request in server.incoming_requests() {
        let state = Arc::clone(&state);
        std::thread::spawn(move || handle(&state, request));
    }
}
