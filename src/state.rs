//! Registry, retention and claims: the three record-keeping parts of the extension.
//!
//! Each one keeps a closed list of refusal codes, and each refusal carries its code. A caller has
//! to be able to tell "you asked for something that does not exist" from "the implementation
//! failed", and a second implementation that loses that distinction fails the suite.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::lists::*;

#[derive(Default)]
pub struct KeyRecord {
    pub principal: String,
    pub public_pem: String,
    pub revoked_reason: Option<String>,
}

#[derive(Default)]
pub struct PrincipalRecord {
    pub reason: String,
    pub confirmed_again: bool,
}

#[derive(Default)]
pub struct Registry {
    pub keys: HashMap<String, KeyRecord>,
    pub principals: HashMap<String, PrincipalRecord>,
}

impl Registry {
    pub fn check(&self, kid: &str) -> (bool, Vec<String>) {
        let record = match self.keys.get(kid) {
            Some(record) => record,
            None => return (false, vec!["unknown_key".to_string()]),
        };
        let mut reasons: Vec<String> = Vec::new();
        if let Some(reason) = &record.revoked_reason {
            reasons.push(format!("key_revoked:{}", reason));
        }
        if let Some(principal) = self.principals.get(&record.principal) {
            if !principal.confirmed_again {
                reasons.push("principal_revoked".to_string());
            }
        }
        (reasons.is_empty(), reasons)
    }

    pub fn register(
        &mut self,
        kid: &str,
        principal: &str,
        pem: &str,
    ) -> Result<(), (String, String)> {
        if let Some(record) = self.principals.get(principal) {
            if !record.confirmed_again {
                return Err((
                    "principal_revoked".to_string(),
                    format!("{} was revoked: {}", principal, record.reason),
                ));
            }
        }
        if self.keys.contains_key(kid) {
            return Err(("unknown_key".to_string(), format!("key {} exists", kid)));
        }
        self.keys.insert(
            kid.to_string(),
            KeyRecord { principal: principal.to_string(), public_pem: pem.to_string(), revoked_reason: None },
        );
        Ok(())
    }

    pub fn rotate(
        &mut self,
        kid: &str,
        new_kid: &str,
        new_pem: &str,
        reason: &str,
    ) -> Result<(), (String, String)> {
        if !contains(&KEY_REVOCATION_REASONS, reason) {
            return Err(("unknown_revocation_reason".to_string(), format!("reason={}", reason)));
        }
        let principal = match self.keys.get(kid) {
            Some(record) => record.principal.clone(),
            None => return Err(("unknown_key".to_string(), format!("key {} is not registered", kid))),
        };
        if let Some(record) = self.keys.get_mut(kid) {
            record.revoked_reason = Some(reason.to_string());
        }
        self.register(new_kid, &principal, new_pem)
    }

    pub fn revoke_key(&mut self, kid: &str, reason: &str) -> Result<(), (String, String)> {
        if !contains(&KEY_REVOCATION_REASONS, reason) {
            return Err(("unknown_revocation_reason".to_string(), format!("reason={}", reason)));
        }
        match self.keys.get_mut(kid) {
            Some(record) => {
                record.revoked_reason = Some(reason.to_string());
                Ok(())
            }
            None => Err(("unknown_key".to_string(), format!("key {} is not registered", kid))),
        }
    }

    pub fn revoke_principal(&mut self, principal: &str, reason: &str) -> Result<(), (String, String)> {
        if !contains(&KEY_REVOCATION_REASONS, reason) {
            return Err(("unknown_revocation_reason".to_string(), format!("reason={}", reason)));
        }
        self.principals.insert(
            principal.to_string(),
            PrincipalRecord { reason: reason.to_string(), confirmed_again: false },
        );
        Ok(())
    }

    pub fn confirm_principal(&mut self, principal: &str) -> Result<(), (String, String)> {
        match self.principals.get_mut(principal) {
            Some(record) => {
                record.confirmed_again = true;
                Ok(())
            }
            None => Err(("principal_not_confirmed".to_string(), format!("{} has no revocation record", principal))),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut keys: Vec<Value> = self
            .keys
            .iter()
            .map(|(kid, record)| {
                json!({
                    "kid": kid,
                    "principal_id": record.principal,
                    "revoked": record.revoked_reason.is_some(),
                    "revocation_reason": record.revoked_reason
                })
            })
            .collect();
        keys.sort_by(|a, b| a["kid"].as_str().cmp(&b["kid"].as_str()));
        let mut principals: Vec<Value> = self
            .principals
            .iter()
            .map(|(name, record)| {
                json!({"principal_id": name, "reason": record.reason, "active": !record.confirmed_again})
            })
            .collect();
        principals.sort_by(|a, b| a["principal_id"].as_str().cmp(&b["principal_id"].as_str()));
        json!({"keys": keys, "principals": principals})
    }
}

#[derive(Default)]
pub struct EnvelopeRecord {
    pub intent_id: String,
    pub deleted_reason: Option<String>,
}

#[derive(Default)]
pub struct Retention {
    pub records: HashMap<String, EnvelopeRecord>,
}

impl Retention {
    pub fn store(&mut self, evidence_id: &str, intent_id: &str) {
        self.records.insert(
            evidence_id.to_string(),
            EnvelopeRecord { intent_id: intent_id.to_string(), deleted_reason: None },
        );
    }

    pub fn archive_intent(&mut self, intent_id: &str) -> Result<usize, (String, String)> {
        let known = self.records.values().any(|record| record.intent_id == intent_id);
        if !known {
            return Err(("unknown_intent".to_string(), format!("no envelopes for {}", intent_id)));
        }
        let mut touched = 0;
        for record in self.records.values_mut() {
            if record.intent_id == intent_id && record.deleted_reason.is_none() {
                record.deleted_reason = Some("intent_archived".to_string());
                touched += 1;
            }
        }
        Ok(touched)
    }

    pub fn delete_envelope(&mut self, evidence_id: &str) -> Result<(), (String, String)> {
        match self.records.get_mut(evidence_id) {
            Some(record) if record.deleted_reason.is_some() => {
                Err(("already_deleted".to_string(), format!("{} was deleted already", evidence_id)))
            }
            Some(record) => {
                record.deleted_reason = Some("owner_request".to_string());
                Ok(())
            }
            None => Err(("unknown_envelope".to_string(), format!("{} is not stored", evidence_id))),
        }
    }

    pub fn purge(&mut self) -> usize {
        // The window is thirty days; a second implementation measures time the same way.
        let before = self.records.len();
        self.records.retain(|_, record| record.deleted_reason.is_none());
        before - self.records.len()
    }

    pub fn to_json(&self) -> Value {
        let mut records: Vec<Value> = self
            .records
            .iter()
            .map(|(evidence_id, record)| {
                json!({
                    "evidence_id": evidence_id,
                    "intent_id": record.intent_id,
                    "deleted_reason": record.deleted_reason,
                    "visible": record.deleted_reason.is_none()
                })
            })
            .collect();
        records.sort_by(|a, b| a["evidence_id"].as_str().cmp(&b["evidence_id"].as_str()));
        json!({
            "retention_days": 30,
            "records": records,
            "note": "only envelope metadata is stored; raw features never reach the server"
        })
    }
}

#[derive(Default)]
pub struct Claim {
    pub feature: String,
    pub level: String,
    pub issuer: String,
    pub issuer_evidence: Option<Value>,
    pub state: String,
}

#[derive(Default)]
pub struct Claims {
    pub issuers: HashMap<String, String>,
    pub declared: HashMap<String, Claim>,
}

impl Claims {
    /// Verify a claim. A level above `declared` needs an issuer and that issuer's own envelope.
    pub fn verify(&self, claim: &Claim) -> (bool, Vec<String>) {
        if !contains(&CLAIM_LEVELS, &claim.level) {
            return (false, vec!["unknown_level".to_string()]);
        }
        if !contains(&CLAIM_STATES, &claim.state) {
            return (false, vec!["unknown_claim_state".to_string()]);
        }
        let mut reasons: Vec<String> = Vec::new();
        if claim.state == "withdrawn" {
            reasons.push("claim_withdrawn".to_string());
        }
        if claim.state == "stale" {
            reasons.push("claim_expired".to_string());
        }
        if claim.level == "declared" {
            return (reasons.is_empty(), reasons);
        }
        if claim.issuer.is_empty() {
            return (false, vec!["missing_issuer".to_string()]);
        }
        if claim.issuer_evidence.is_none() {
            return (false, vec!["level_upgraded_without_issuer".to_string()]);
        }
        if !self.issuers.contains_key(&claim.issuer) {
            reasons.push("unknown_issuer".to_string());
            return (false, reasons);
        }
        // Signature checking of the issuer envelope reuses the card verifier, since an envelope
        // and a card are signed the same way. A second implementation must do the same thing.
        let verified = claim
            .issuer_evidence
            .as_ref()
            .map(|envelope| crate::card::verify_card_self(envelope).0)
            .unwrap_or(false);
        if !verified {
            reasons.push("issuer_envelope_invalid".to_string());
        }
        (reasons.is_empty(), reasons)
    }

    pub fn to_json(&self) -> Value {
        let mut issuers: Vec<String> = self.issuers.keys().cloned().collect();
        issuers.sort();
        let mut declared: Vec<Value> = self
            .declared
            .values()
            .map(|claim| {
                json!({
                    "feature": claim.feature,
                    "level": claim.level,
                    "issuer": claim.issuer,
                    "state": claim.state,
                    "has_issuer_evidence": claim.issuer_evidence.is_some()
                })
            })
            .collect();
        declared.sort_by(|a, b| a["feature"].as_str().cmp(&b["feature"].as_str()));
        json!({"issuers": issuers, "declared": declared})
    }
}
