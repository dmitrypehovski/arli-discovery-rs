//! Second implementation of the ARLI Discovery Extension.
//!
//! Why it exists. The Python engine is the readable reference. This one answers the question a
//! standard lives or dies on: can somebody else implement the text from the text? So the lists
//! and the rules here were written from the normative document, and the conformance suite is the
//! judge. Where the two implementations disagree, the disagreement is the interesting part.
//!
//! Every method of the published surface is implemented here, and the conformance suite is the
//! judge of that: it reports thirty checks and no mismatches.

mod canon;
mod caps;
mod card;
mod lists;
mod psi;
mod state;

use std::collections::HashMap;
use std::sync::OnceLock;
use std::env;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Method, Response, Server};

const MIN_NONCE_CHARS: usize = 16;
const IDENTITY_WINDOW_SECONDS: u64 = 60;

use canon::canonical;
use lists::*;
use state::{Claim, Claims, Registry, Retention};

pub struct AgentState {
    pub name: String,
    pub features: Vec<String>,
    pub epoch: Option<psi::EpochKey>,
    pub psi_issued: HashMap<String, String>,
    pub epoch_ordinal: u64,
    pub psi_applicant: HashMap<String, (Vec<String>, Vec<num_bigint::BigUint>)>,
    // The identity method must not become a signing oracle: one signed nonce per address and
    // purpose per minute. The address comes from the connection, the purpose from the caller.
    pub peer: String,
    pub identity_requests: HashMap<(String, String), u64>,
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
    // Which way it settled, or nothing while it is open. The other side has to be able to read this from the
    // response: a peer that only hears "settled" cannot tell an agreement from a refusal, and the two live
    // implementations disagreed about exactly this until the text named the field (clause 6.13).
    pub outcome: Option<String>,
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

/// The negotiation grammar, in one place: both the agent's own turn and a witnessed turn of the
/// counterparty go through this, so the rules cannot drift between the two paths.
fn apply_turn(negotiation: &mut Negotiation, seat: &str, action: &str, negotiation_id: &str) -> Result<(), (String, String)> {
    if !contains(&ACTIONS, action) {
        return Err(refusal("unknown_action", action));
    }
    if negotiation.settled {
        return Err(refusal("already_settled", negotiation_id));
    }
    if !negotiation.seats.iter().any(|item| *item == seat) {
        return Err(refusal(
            "not_a_seat",
            &format!("this negotiation seats {}, not {}", negotiation.seats.join(","), seat),
        ));
    }
    if !negotiation.turns.is_empty() {
        let last = negotiation.turns.last().map(|(s, _)| s.clone()).unwrap_or_default();
        if last == seat {
            return Err(refusal("seats_must_alternate", "the same seat cannot take two turns in a row"));
        }
        if action == "accept" {
            let last_action = negotiation.turns.last().map(|(_, a)| a.clone()).unwrap_or_default();
            if last_action != "propose" {
                return Err(refusal("accept_without_offer", "accept is legal only right after a propose"));
            }
        }
    } else if action == "accept" || action == "counter" {
        return Err(refusal("first_turn_is_propose_or_decline", "the initiator owes the first turn"));
    }
    if negotiation.turns.len() as u32 >= MAX_TURNS {
        return Err(refusal("turn_limit", "the turn limit is reached; the negotiation stays unsettled"));
    }
    if action == "accept" || action == "decline" {
        negotiation.settled = true;
        negotiation.outcome = Some(if action == "accept" { "agreed".to_string() } else { "declined".to_string() });
    }
    negotiation.turns.push((seat.to_string(), action.to_string()));
    Ok(())
}


/// The bucket space this agent counts in, read once from the taxonomy file the deployment names.
///
/// No file means no space: the profile is then empty and named empty, so a room asks this agent on every
/// search instead of skipping it. Guessing a bucket would be a wrong skip, which is worse than a slow search.
fn bucket_space() -> (Option<HashMap<String, String>>, String) {
    static SPACE: OnceLock<(Option<HashMap<String, String>>, String)> = OnceLock::new();
    SPACE
        .get_or_init(|| {
            let path = std::env::var("ARLI_TAXONOMY").unwrap_or_default();
            if path.is_empty() || !std::path::Path::new(&path).is_file() {
                return (None, String::new());
            }
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(_) => return (None, String::new()),
            };
            let parsed: Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(_) => return (None, String::new()),
            };
            let mut map: HashMap<String, String> = HashMap::new();
            if let Some(object) = parsed.as_object() {
                for (category, node) in object {
                    if let Some(subcategories) = node.get("subcategories").and_then(|value| value.as_object()) {
                        for slug in subcategories.keys() {
                            map.insert(slug.clone(), category.clone());
                        }
                    }
                }
            }
            (Some(map), format!("taxonomy:{}", path))
        })
        .clone()
}


fn dispatch(state: &mut AgentState, method: &str, params: &Value) -> Result<Value, (String, String)> {
    match method {
        "agent/card" => Ok(json!({"card": state.card})),
        "arli/capabilities" => Ok(caps::capability_document()),
        // What this agent publishes about itself: buckets, never items. The bucket space is named because
        // two spaces are not comparable, and an agent whose items cannot be placed must not look like one
        // with nothing to offer.
        "arli/profile" => {
            let (space, space_name) = bucket_space();
            let mut buckets: HashMap<String, i64> = HashMap::new();
            if let Some(map) = space {
                for feature in &state.features {
                    let slug = feature.split_once(':').map(|(_, value)| value).unwrap_or(feature.as_str());
                    if let Some(category) = map.get(slug) {
                        *buckets.entry(category.clone()).or_insert(0) += 1;
                    }
                }
            }
            Ok(json!({
                "buckets": buckets,
                "bucket_space": space_name,
                "kind": "",
                "city": "",
                "feature_count": state.features.len(),
                "note": "No item value is in this answer. A search still runs a real exchange; the bucket only decides who is worth one."
            }))
        }

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
            let now = psi::now_seconds();
            let ttl = epoch_seconds();
            state.epoch_ordinal += 1;
            if state.epoch.as_ref().map(|e| e.expired(now)).unwrap_or(true) {
                let ordinal = state.epoch_ordinal;
                state.epoch = Some(psi::EpochKey::new(ttl, ordinal));
            }
            // The key lasts an epoch, and the session is bound to the epoch that issued it.
            let (epoch_id, n_hex, e_hex, seconds_left) = {
                let epoch = state.epoch.as_ref().expect("epoch just ensured");
                (
                    epoch.id.clone(),
                    psi::to_hex(&epoch.key.n),
                    psi::to_hex(&epoch.key.e),
                    epoch.seconds_left(now),
                )
            };
            state.psi_issued.insert(session, epoch_id.clone());
            Ok(json!({
                "scheme": "closed_blind_rsa",
                "feature_cap": FEATURE_CAP,
                "n": n_hex,
                "e": e_hex,
                "epoch_id": epoch_id,
                "epoch_expires_in_seconds": seconds_left,
                "note": "the private exponent never leaves this agent; the key lasts one epoch and then expires"
            }))
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
            let now = psi::now_seconds();
            if state.epoch.as_ref().map(|e| e.expired(now)).unwrap_or(true) {
                return Err(refusal(
                    "missing_private_key",
                    "the epoch that issued this session's key has expired; keys are per epoch, not for ever",
                ));
            }
            let epoch_id = state
                .epoch
                .as_ref()
                .map(|e| e.id.clone())
                .unwrap_or_default();
            match state.psi_issued.get(&session) {
                None => {
                    return Err(refusal(
                        "missing_private_key",
                        "no key was issued for this session yet",
                    ))
                }
                Some(issued) if issued != &epoch_id => {
                    return Err(refusal(
                        "missing_private_key",
                        "the epoch that issued this session's key has expired; keys are per epoch, not for ever",
                    ))
                }
                Some(_) => {}
            }
            let features = state.features.clone();
            let epoch = state.epoch.as_mut().expect("epoch checked above");
            let d = epoch.key.d.clone();
            let n = epoch.key.n.clone();
            // Signing the seeker's values is per exchange and nobody else can do it for us; our own tokens
            // come from the epoch table and are computed once for every seeker in this epoch.
            let signed: Vec<String> = values
                .iter()
                .map(|value| {
                    let blinded = psi::from_hex(value.as_str().unwrap_or_default());
                    psi::to_hex(&psi::token(&blinded, &d, &n))
                })
                .collect();
            let holder_tokens: Vec<String> = epoch
                .tokens_for(&features)
                .iter()
                .map(|value| psi::to_hex(value))
                .collect();
            Ok(json!({
                "epoch_id": epoch_id,
                "signed": signed,
                "holder_tokens": holder_tokens
            }))
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
                Negotiation { seats: peers, turns: Vec::new(), settled: false, outcome: None, closed: false },
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
            let negotiation_id = params["negotiation_id"].as_str().unwrap_or_default().to_string();
            let seat = params["seat"].as_str().unwrap_or_default().to_string();
            let action = params["action"].as_str().unwrap_or_default().to_string();
            if seat != state.name {
                return Err(refusal(
                    "not_a_seat",
                    &format!("this agent holds seat {}, not {}", state.name, seat),
                ));
            }
            let negotiation = match state.negotiations.get_mut(&negotiation_id) {
                Some(negotiation) => negotiation,
                None => {
                    return Err(refusal(
                        "unknown_negotiation",
                        &format!("unknown negotiation: {}", negotiation_id),
                    ))
                }
            };
            apply_turn(negotiation, &seat, &action, &negotiation_id)?;
            let turns = negotiation.turns.len();
            let outcome = negotiation.outcome.clone();
            let evidence = envelope(
                &state.signer,
                "negotiation_turn",
                json!({"negotiation_id": negotiation_id, "seat": seat, "action": action}),
                json!({"outcome": outcome, "turn_count": turns, "turn_limit": MAX_TURNS}),
                vec!["A turn is recorded once, in this agent's own journal."],
            );
            // The response fields are the text's (clause 6.13), not this implementation's invention: a caller
            // reads the outcome, and null means the negotiation is still open.
            Ok(json!({
                "outcome": outcome,
                "turn_count": turns,
                "turns_remaining": MAX_TURNS.saturating_sub(turns as u32),
                "evidence": evidence
            }))
        }
        "arli/negotiation/witness" => {
            for field in ["negotiation_id", "seat", "action", "proof", "card"] {
                require(params, field)?;
            }
            let negotiation_id = params["negotiation_id"].as_str().unwrap_or_default().to_string();
            let seat = params["seat"].as_str().unwrap_or_default().to_string();
            let action = params["action"].as_str().unwrap_or_default().to_string();
            if seat == state.name {
                return Err(refusal(
                    "not_a_witness",
                    "an agent takes its own turns with the turn method; witnessing is for the other side",
                ));
            }
            let proof = params.get("proof").cloned().unwrap_or(Value::Null);
            if !proof.is_object() {
                return Err(refusal("witness_without_proof", "the speaker's envelope is required"));
            }
            let card = params.get("card").cloned().unwrap_or(Value::Null);
            if !card.is_object() {
                return Err(refusal("witness_card_unverified", "the speaker's signed card is required"));
            }
            let (verified, reasons) = card::verify_card_self(&card);
            if !verified {
                return Err(refusal("witness_card_unverified", &reasons.join("; ")));
            }
            let card_name = card.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            if card_name != seat {
                return Err(refusal(
                    "witness_seat_mismatch",
                    &format!("the card names {}, the witnessed seat is {}", card_name, seat),
                ));
            }
            let key = match card::card_verifying_key(&card) {
                Some(key) => key,
                None => {
                    return Err(refusal(
                        "witness_card_unverified",
                        "the card carries no usable public key",
                    ))
                }
            };
            if let Err(reason) = card::verify_envelope(&proof, &key) {
                return Err(refusal("witness_proof_invalid", &reason));
            }
            let recorded = proof.get("parameters").cloned().unwrap_or_else(|| json!({}));
            let recorded_seat = recorded.get("seat").and_then(|v| v.as_str()).unwrap_or_default();
            let recorded_action = recorded.get("action").and_then(|v| v.as_str()).unwrap_or_default();
            if recorded_seat != seat || recorded_action != action {
                return Err(refusal(
                    "witness_mismatch",
                    &format!(
                        "the envelope records seat {} and action {}, the request names {} and {}",
                        recorded_seat, recorded_action, seat, action
                    ),
                ));
            }
            let negotiation = match state.negotiations.get_mut(&negotiation_id) {
                Some(negotiation) => negotiation,
                None => {
                    return Err(refusal(
                        "unknown_negotiation",
                        &format!("unknown negotiation: {}", negotiation_id),
                    ))
                }
            };
            apply_turn(negotiation, &seat, &action, &negotiation_id)?;
            let turns = negotiation.turns.len();
            let settled = negotiation.settled;
            let evidence = envelope(
                &state.signer,
                "negotiation_witness",
                json!({"negotiation_id": negotiation_id, "seat": seat, "action": action}),
                json!({"turns": turns, "settled": settled}),
                vec!["A witnessed turn is the counterparty's own, checked against its signed card."],
            );
            Ok(json!({"recorded": true, "turns": turns, "settled": settled, "evidence": evidence}))
        }
        "arli/identity/sign" => {
            for field in ["nonce", "purpose"] {
                require(params, field)?;
            }
            let nonce = params["nonce"].as_str().unwrap_or_default();
            if nonce.chars().count() < MIN_NONCE_CHARS {
                return Err(refusal(
                    "nonce_too_short",
                    &format!("a nonce of at least {} characters is required", MIN_NONCE_CHARS),
                ));
            }
            let purpose = params["purpose"].as_str().unwrap_or_default().trim().to_lowercase();
            if purpose.is_empty() {
                return Err(refusal("purpose_required", "name what the signature is for"));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let window = (state.peer.clone(), purpose.clone());
            if let Some(last) = state.identity_requests.get(&window) {
                if now.saturating_sub(*last) < IDENTITY_WINDOW_SECONDS {
                    return Err(refusal(
                        "rate_limited",
                        &format!(
                            "one signed nonce per address and purpose per {}s",
                            IDENTITY_WINDOW_SECONDS
                        ),
                    ));
                }
            }
            state.identity_requests.insert(window, now);

            // Sign the bytes exactly as they were sent: that is what makes the proof checkable.
            let signature: Signature = state.signer.key.sign(nonce.as_bytes());
            Ok(json!({
                "signature": B64.encode(signature.to_bytes()),
                "kid": state.signer.kid,
                "alg": "ES256",
                "purpose": purpose,
                "signed_bytes": nonce.as_bytes().len(),
            }))
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
            // A refusal is not an agreement: consent is only considered after an agreed outcome (clause 6.14).
            if negotiation.outcome.as_deref() != Some("agreed") {
                return Err(refusal("not_agreed", "humans decide only after the agents agreed"));
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

        // Every method of the published surface is implemented here; anything else is not a
        // method of this extension at all.
        _ => Err(refusal("unknown_method", &format!("unknown method: {}", method))),
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
            let peer = request.remote_addr().map(|addr| addr.ip().to_string()).unwrap_or_default();
            let outcome = {
                let mut guard = state.lock().unwrap();
                guard.peer = peer;
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

/// How long an epoch lasts. Overridable so the expiry can be exercised instead of believed.
fn epoch_seconds() -> u64 {
    std::env::var("ARLI_EPOCH_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(psi::DEFAULT_EPOCH_SECONDS)
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
                    .map(|value| {
                        // An empty flag value is an empty list, not a list holding one empty string: the
                        // second reads as a feature nobody wrote, and the conformance kit caught it as an
                        // empty match at the floor check.
                        value
                            .split(',')
                            .map(|part| part.trim().to_string())
                            .filter(|part| !part.is_empty())
                            .collect()
                    })
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
        epoch: None,
        psi_issued: HashMap::new(),
        epoch_ordinal: 0,
        psi_applicant: HashMap::new(),
        peer: String::new(),
        identity_requests: HashMap::new(),
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
