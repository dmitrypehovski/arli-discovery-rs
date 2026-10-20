//! The closed lists of the extension, written out once.
//!
//! A second implementation exists to answer one question: is the text implementable by somebody
//! who did not write the first implementation? Therefore these lists are typed out from the
//! normative text, not copied from the Python code. Where they disagree, the conformance suite
//! says so, and that is the interesting case.

pub const EXTENSION_URI: &str = "https://arliwork.com/a2a/extensions/arli.discovery.v1";
pub const EXTENSION_VERSION: &str = "1.1.0";

pub const EFFECT_KEYS: [&str; 7] = [
    "mutates_artifact",
    "launches_process",
    "may_show_ui",
    "may_access_network",
    "may_write_filesystem",
    "changes_permissions",
    "requires_root",
];

pub const AVAILABILITY_CODES: [&str; 5] = [
    "available",
    "unsupported_host",
    "missing_dependency",
    "not_configured",
    "disabled_by_policy",
];

pub const MAX_TURNS: u32 = 12;

pub const ACTIONS: [&str; 4] = ["propose", "counter", "accept", "decline"];

pub const TURN_REJECTIONS: [&str; 9] = [
    "not_a_seat",
    "unknown_action",
    "already_settled",
    "turn_limit",
    "not_your_turn",
    "first_turn_is_propose_or_decline",
    "seats_must_alternate",
    "accept_without_offer",
    "propose_over_offer",
];

pub const OPENING_REJECTIONS: [&str; 7] = [
    "intent_inactive",
    "synthetic_not_admitted",
    "same_owner",
    "same_intent",
    "network_mismatch",
    "types_not_comparable",
    "below_required_level",
];

pub const MATCH_REJECTIONS: [&str; 7] = [
    "too_many_features",
    "missing_pair_key",
    "missing_peer_key",
    "missing_private_key",
    "length_mismatch",
    "missing_floor",
    "invalid_floor",
];

pub const INTENT_REJECTIONS: [&str; 7] = [
    "unknown_type",
    "unknown_status",
    "unknown_provenance",
    "synthetic_not_admitted",
    "intent_inactive",
    "types_not_comparable",
    "network_mismatch",
];

pub const RETENTION_REJECTIONS: [&str; 3] =
    ["unknown_envelope", "already_deleted", "unknown_intent"];

pub const CLAIM_LEVELS: [&str; 3] = ["declared", "third_party_verified", "topic_owner_verified"];

pub const CLAIM_STATES: [&str; 3] = ["active", "stale", "withdrawn"];

pub const CLAIM_REJECTIONS: [&str; 9] = [
    "unknown_level",
    "unknown_claim_state",
    "missing_issuer",
    "unknown_issuer",
    "issuer_envelope_invalid",
    "claim_expired",
    "claim_withdrawn",
    "level_upgraded_without_issuer",
    "missing_checked_at",
];

pub const REGISTRY_REJECTIONS: [&str; 7] = [
    "unknown_key",
    "key_revoked",
    "key_expired",
    "key_not_yet_valid",
    "principal_revoked",
    "principal_not_confirmed",
    "unknown_revocation_reason",
];

pub const KEY_REVOCATION_REASONS: [&str; 4] =
    ["rotated", "compromised", "principal_request", "policy"];

pub const CALL_REJECTIONS: [&str; 5] = [
    "missing_field",
    "unknown_method",
    "parse_error",
    "bad_type",
    "not_implemented",
];

pub const CONFIDENCE_VALUES: [&str; 4] = ["observed", "derived", "claimed", "unknown"];

pub const INTENT_TYPES: [&str; 3] = ["person", "supply", "demand"];
pub const INTENT_STATUSES: [&str; 3] = ["active", "paused", "archived"];
pub const PROVENANCE: [&str; 3] = ["human", "organisation", "synthetic"];

pub const FEATURE_CAP: usize = 64;

/// The surface, in the order the text lists it. One list, and every binding must agree with it.
pub const METHOD_NAMES: [&str; 26] = [
    "agent/card",
    "arli/capabilities",
    "arli/commitments",
    "arli/match",
    "arli/psi/keys",
    "arli/psi/commit",
    "arli/psi/sign",
    "arli/psi/finish",
    "arli/psi/record",
    "arli/registry/status",
    "arli/registry/register",
    "arli/registry/rotate",
    "arli/registry/revoke",
    "arli/registry/confirm",
    "arli/registry/check",
    "arli/retention/status",
    "arli/retention/record",
    "arli/retention/archive",
    "arli/retention/delete",
    "arli/retention/purge",
    "arli/claims/status",
    "arli/claims/issuers",
    "arli/claims/declare",
    "arli/negotiation/open",
    "arli/negotiation/turn",
    "arli/opportunity/decide",
];

pub fn tool_name(method: &str) -> String {
    method.replace('/', "_")
}

pub fn contains(list: &[&str], value: &str) -> bool {
    list.iter().any(|item| *item == value)
}
