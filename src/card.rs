//! The agent card, signed so that a reader can verify it with the key carried in its own header.
//!
//! This is the part of the text a reader hits first, and it is where a second implementation
//! either matches or does not: the signature format, the header fields, and what is excluded
//! from the signed body all have to agree with what the text and the suite expect.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use serde_json::{json, Value};

use crate::canon;
use crate::lists::EXTENSION_URI;

pub const SIGNED_FIELD: &str = "signatures";

pub struct Signer1 {
    pub key: SigningKey,
    pub kid: String,
}

impl Signer1 {
    pub fn random(kid: &str) -> Self {
        Signer1 { key: SigningKey::random(&mut OsRng), kid: kid.to_string() }
    }

    pub fn verifying(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }

    fn jwk(&self) -> Value {
        let point = self.verifying().to_encoded_point(false);
        let x = point.x().map(|v| v.to_vec()).unwrap_or_default();
        let y = point.y().map(|v| v.to_vec()).unwrap_or_default();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "kid": self.kid,
            "x": B64.encode(x),
            "y": B64.encode(y),
        })
    }

    pub fn sign_card(&self, body: &Value) -> Value {
        let header = json!({"alg": "ES256", "kid": self.kid, "typ": "JOSE", "jwk": self.jwk()});
        let protected = B64.encode(canon::canonical(&header).as_bytes());
        let payload = B64.encode(canon::canonical(body).as_bytes());
        let signing_input = format!("{}.{}", protected, payload);
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        let value = B64.encode(signature.to_bytes());
        json!({"protected": protected, "signature": value})
    }
}

pub fn build_card(signer: &Signer1, name: &str, base_url: &str) -> Value {
    let mut body = json!({
        "name": name,
        "description": format!("{}: ARLI discovery agent, second implementation", name),
        "version": "0.1.0",
        "provider": {
            "organization": "Shenzhen Capernaum Technology Co., Ltd.",
            "url": "https://arliwork.com"
        },
        "capabilities": {"streaming": false, "pushNotifications": false, "extendedAgentCard": false},
        "skills": [{
            "id": "discover.match",
            "name": "Closed intersection",
            "description": "Match intents without an index holder.",
            "inputModes": ["application/json"],
            "outputModes": ["application/json"]
        }],
        "interfaces": [{
            "url": format!("{}/a2a/rpc", base_url),
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0"
        }],
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "extensions": [{
            "uri": EXTENSION_URI,
            "description": "Verified discovery: honest capability manifest, matching without an index holder, evidence on every conclusion and refusal.",
            "required": false,
            "params": {
                "capabilities_url": format!("{}/.well-known/arli-capabilities.json", base_url),
                "negotiation_grammar": "propose|counter|accept|decline, max 12 turns",
                "consent": "agent agreement never opens a connection without principal approval",
                "evidence": "envelopes are signed by the agent key; verification is required to count"
            }
        }]
    });
    let signature = signer.sign_card(&body);
    if let Some(map) = body.as_object_mut() {
        map.insert(SIGNED_FIELD.to_string(), json!([signature]));
    }
    body
}

fn verify_with_jwk(body: &Value, jwk: &Value, protected: &str, signature: &str) -> Result<(), String> {
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or_default();
    if crv != "P-256" {
        return Err(format!("unsupported curve: {}", crv));
    }
    let x = B64.decode(jwk.get("x").and_then(|v| v.as_str()).unwrap_or_default())
        .map_err(|e| format!("x is not base64url: {}", e))?;
    let y = B64.decode(jwk.get("y").and_then(|v| v.as_str()).unwrap_or_default())
        .map_err(|e| format!("y is not base64url: {}", e))?;
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let point = p256::EncodedPoint::from_bytes(&sec1).map_err(|e| format!("bad point: {}", e))?;
    let key = VerifyingKey::from_encoded_point(&point).map_err(|e| format!("bad key: {}", e))?;
    let raw = B64.decode(signature).map_err(|e| format!("signature is not base64url: {}", e))?;
    let sig = Signature::from_slice(&raw).map_err(|e| format!("bad signature: {}", e))?;
    let payload = B64.encode(canon::canonical(body).as_bytes());
    let signing_input = format!("{}.{}", protected, payload);
    key.verify(signing_input.as_bytes(), &sig).map_err(|_| "signature does not verify".to_string())
}

/// The public key of the card's own signature header.
///
/// A card binds a key to a name, so a signature that verifies against this key belongs to whoever
/// the card names. Used by the witness step, where that is the whole point.
pub fn card_verifying_key(card: &Value) -> Option<VerifyingKey> {
    let entries = card.get(SIGNED_FIELD).and_then(|v| v.as_array())?;
    let entry = entries.first()?;
    let protected = entry.get("protected").and_then(|v| v.as_str())?;
    let header: Value = B64.decode(protected).ok().and_then(|raw| serde_json::from_slice(&raw).ok())?;
    let jwk = header.get("jwk")?;
    let x = B64.decode(jwk.get("x").and_then(|v| v.as_str())?).ok()?;
    let y = B64.decode(jwk.get("y").and_then(|v| v.as_str())?).ok()?;
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_encoded_point(&p256::EncodedPoint::from_bytes(&sec1).ok()?).ok()
}

/// Verify an envelope signature: the body without the signature itself, signed with ES256.
pub fn verify_envelope(envelope: &Value, key: &VerifyingKey) -> Result<(), String> {
    let value = envelope
        .get("signature")
        .and_then(|entry| entry.get("value"))
        .and_then(|text| text.as_str())
        .ok_or_else(|| "envelope has no signature".to_string())?;
    let raw = B64.decode(value).map_err(|error| format!("signature is not base64url: {}", error))?;
    let signature = Signature::from_slice(&raw).map_err(|error| format!("bad signature: {}", error))?;
    let mut body = envelope.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("signature");
    }
    key.verify(canon::canonical(&body).as_bytes(), &signature)
        .map_err(|_| "signature does not match the envelope body".to_string())
}

/// Verify a card with the key from its own header. This is what any other party can do.
pub fn verify_card_self(card: &Value) -> (bool, Vec<String>) {
    let entries = match card.get(SIGNED_FIELD).and_then(|v| v.as_array()) {
        Some(list) if !list.is_empty() => list.clone(),
        _ => return (false, vec!["card carries no signature".to_string()]),
    };
    let entry = &entries[0];
    let protected = entry.get("protected").and_then(|v| v.as_str()).unwrap_or_default();
    let signature = entry.get("signature").and_then(|v| v.as_str()).unwrap_or_default();
    if protected.is_empty() || signature.is_empty() {
        return (false, vec!["signature entry is incomplete".to_string()]);
    }
    let header: Value = match B64.decode(protected).ok().and_then(|raw| serde_json::from_slice(&raw).ok()) {
        Some(value) => value,
        None => return (false, vec!["protected header is not base64url JSON".to_string()]),
    };
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return (false, vec!["unsupported alg".to_string()]);
    }
    let jwk = match header.get("jwk") {
        Some(value) => value.clone(),
        None => return (false, vec!["card header carries no jwk".to_string()]),
    };
    let mut body = card.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove(SIGNED_FIELD);
    }
    match verify_with_jwk(&body, &jwk, protected, signature) {
        Ok(()) => (true, Vec::new()),
        Err(reason) => (false, vec![reason]),
    }
}
