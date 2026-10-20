//! The capability document: what the agent can do, what it cannot, and the closed lists.
//!
//! The text requires this to be published by machine rather than in prose, so it is built from
//! the lists module. A reader comparing two implementations should find the same lists here, and
//! the suite fails the pair when they differ.

use serde_json::{json, Value};

use crate::canon;
use crate::lists::*;

fn operation(name: &str, description: &str, available: bool, reason: Option<&str>) -> Value {
    let effects = canon::object(
        EFFECT_KEYS
            .iter()
            .map(|key| (*key, Value::Bool(*key == "may_access_network")))
            .collect(),
    );
    let mut entry = json!({
        "name": name,
        "description": description,
        "available": available,
        "declared_effect_keys": EFFECT_KEYS.to_vec(),
        "effects": effects,
        "availability_code": if available { "available" } else { reason.unwrap_or("disabled_by_policy") },
    });
    if !available {
        entry["availability_reason"] =
            Value::String("An agent acts only for its own principal.".to_string());
    }
    entry
}

pub fn capability_document() -> Value {
    json!({
        "manifest": {
            "open": false,
            "operation_count": 2,
            "fail_closed": true,
            "operations": [
                operation("discover.match", "Match intents without an index holder.", true, None),
                operation("act.as.other", "Act for another principal", false, Some("disabled_by_policy")),
            ],
            "operations_with_undeclared_effects": [],
            "notes": [
                "An undeclared effect is treated as possible, not as absent.",
                "The seven effect keys are declared for every operation."
            ]
        },
        "extension_uri": EXTENSION_URI,
        "extension_version": EXTENSION_VERSION,
        "negotiation_rules": {
            "max_turns": MAX_TURNS,
            "actions": ACTIONS.to_vec(),
            "turn_rejections": TURN_REJECTIONS.to_vec(),
            "opening_rejections": OPENING_REJECTIONS.to_vec()
        },
        "intersection": {
            "scheme": "closed_blind_rsa",
            "feature_cap": FEATURE_CAP,
            "closed": "offline enumeration of the counterparty's features",
            "not_closed": "online probing of a single guess, because any set intersection answers for every element submitted; bounded by one exchange per session",
            "callers_learn": "matches among their own features, and the holder learns the submission count",
            "match_rejections": MATCH_REJECTIONS.to_vec()
        },
        "intent": {
            "types": INTENT_TYPES.to_vec(),
            "statuses": INTENT_STATUSES.to_vec(),
            "provenance": PROVENANCE.to_vec(),
            "comparable": "supply with demand, person with person; two supplies or two demands are not a match",
            "synthetic": "a network declares whether it admits synthetic intents; by default it does not",
            "intent_rejections": INTENT_REJECTIONS.to_vec()
        },
        "bindings": {
            "a2a": {"transport": "http-jsonrpc", "rpc_path": "/a2a/rpc", "methods": METHOD_NAMES.to_vec()},
            "mcp": {
                "transport": "stdio-jsonrpc",
                "naming": "a tool name is a method name with slashes replaced by underscores",
                "tools": METHOD_NAMES.iter().map(|method| tool_name(method)).collect::<Vec<String>>()
            },
            "plugin": {
                "transport": "stdio-jsonrpc",
                "manifest": "arli-discovery",
                "tools": METHOD_NAMES.iter().map(|method| tool_name(method)).collect::<Vec<String>>(),
                "generated": "the manifest is built from the surface, never hand-written"
            },
            "rule": "every binding exposes the same surface: no method added, none hidden"
        },
        "call_rejections": CALL_REJECTIONS.to_vec(),
        "registry": {
            "rotation": "a rotated key stops validating the card; the principal is untouched",
            "principal_revocation": "a separate record; it blocks new keys until the principal is confirmed again",
            "key_revocation_reasons": KEY_REVOCATION_REASONS.to_vec(),
            "registry_rejections": REGISTRY_REJECTIONS.to_vec()
        },
        "retention": {
            "default_days": 30,
            "raw_features": "never stored on the server",
            "archive": "marks the envelopes of an intent deleted and removes them from search",
            "purge": "physically removes records older than the window",
            "retention_rejections": RETENTION_REJECTIONS.to_vec()
        },
        "claims": {
            "levels": CLAIM_LEVELS.to_vec(),
            "states": CLAIM_STATES.to_vec(),
            "claim_rejections": CLAIM_REJECTIONS.to_vec(),
            "issuance": "This implementation relays and verifies statements made by others and issues none of its own.",
            "prohibitions": [
                "A level is not proof of who is behind an agent.",
                "A level is not transferable between networks."
            ]
        },
        "limitations": [
            "Online probing of a single guess is not closed by the scheme.",
            "A signed card proves the publisher of the card, not a person.",
            "This implementation is a second implementation under construction: the matching flow is not finished, and every method that is not finished refuses with the code not_implemented."
        ]
    })
}
