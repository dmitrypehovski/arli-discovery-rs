//! The matching flow: blind RSA intersection, written from the text rather than translated.
//!
//! The point of this file is that nothing secret travels. The applicant blinds its own features
//! with the holder's public key and sends only the blinded values; the holder signs them without
//! learning what they are, and returns signatures over its own features. The applicant unblinds
//! and learns the intersection among its own features, and nothing about the holder's list. The
//! holder learns how many values were submitted, which is stated as a limit in the text.

use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use sha2::{Digest, Sha256};

// The modulus must be the same size as the reference implementation's, or the comparison is
// meaningless and the scheme is not secure at all: a 256-bit RSA modulus is factorable, so a
// smaller number here would buy speed with the whole promise. The text says the scheme is blind
// RSA; the strength of the key is a separate decision, and 2048 bits matches the reference.
pub const MODULUS_BITS: usize = 2048;
pub const EXPONENT: u64 = 65537;

pub struct RsaKey {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
}

fn is_probable_prime(candidate: &BigUint) -> bool {
    // Small primes first: cheap, and it removes most composites before the rounds.
    for small in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let small = BigUint::from(small);
        if candidate == &small {
            return true;
        }
        if (candidate % &small).is_zero() {
            return false;
        }
    }
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let candidate_minus_one = candidate - &one;
    let mut d = candidate_minus_one.clone();
    let mut rounds = 0u32;
    while (&d % &two).is_zero() {
        d /= &two;
        rounds += 1;
    }
    let mut rng = thread_rng();
    for _ in 0..16 {
        let base = rng.gen_biguint_range(&two, &(candidate - &one));
        let mut x = base.modpow(&d, candidate);
        if x == one || x == candidate_minus_one {
            continue;
        }
        let mut composite = true;
        for _ in 0..rounds.saturating_sub(1) {
            x = x.modpow(&two, candidate);
            if x == candidate_minus_one {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

fn random_prime(bits: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        let mut candidate = rng.gen_biguint(bits as u64);
        candidate.set_bit((bits - 1) as u64, true);
        candidate.set_bit(0, true);
        if is_probable_prime(&candidate) {
            return candidate;
        }
    }
}

fn modular_inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    // Extended Euclid over signed integers, then back into the field.
    let (mut old_r, mut r) = (BigInt::from(value.clone()), BigInt::from(modulus.clone()));
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    while !r.is_zero() {
        let quotient = &old_r / &r;
        let new_r = &old_r - &quotient * &r;
        old_r = std::mem::replace(&mut r, new_r);
        let new_s = &old_s - &quotient * &s;
        old_s = std::mem::replace(&mut s, new_s);
    }
    let inverse = ((old_s % BigInt::from(modulus.clone())) + BigInt::from(modulus.clone()))
        % BigInt::from(modulus.clone());
    match inverse.to_biguint() {
        Some(value) => value,
        None => BigUint::one(),
    }
}

impl RsaKey {
    pub fn generate() -> RsaKey {
        let half = MODULUS_BITS / 2;
        loop {
            let p = random_prime(half);
            let q = random_prime(half);
            if p == q {
                continue;
            }
            let n = &p * &q;
            let e = BigUint::from(EXPONENT);
            let phi = (&p - BigUint::one()) * (&q - BigUint::one());
            if (&phi % &e).is_zero() {
                continue;
            }
            let d = modular_inverse(&e, &phi);
            return RsaKey { n, e, d };
        }
    }
}

/// The published vocabulary: what counts as the same thing on both sides.
///
/// A need and an offer of the same commodity have to meet, so a goods namespace reduces to its value
/// and everything else keeps its namespace. Written from the text, not copied from the other
/// implementation: two implementations that agree only because one copied the other prove nothing.
pub fn canonical_token(feature: &str) -> String {
    let text = feature.trim();
    let (namespace, value) = match text.split_once(':') {
        Some((head, tail)) => (head.trim().to_lowercase(), tail.trim().to_lowercase()),
        None => return clean(text),
    };
    let value = clean(&value);
    const GOODS: [&str; 8] =
        ["need", "want", "offer", "supply", "skill", "service", "commodity", "product"];
    if GOODS.contains(&namespace.as_str()) {
        value
    } else {
        format!("{}:{}", namespace, value)
    }
}

fn clean(text: &str) -> String {
    let lowered = text.trim().to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut pending_separator = false;
    for character in lowered.chars() {
        if character.is_whitespace() || character == '_' || character == '-' {
            pending_separator = !out.is_empty();
            continue;
        }
        if pending_separator {
            out.push('-');
            pending_separator = false;
        }
        out.push(character);
    }
    out
}

pub fn feature_hash(feature: &str, n: &BigUint) -> BigUint {
    let digest = Sha256::digest(canonical_token(feature).as_bytes());
    BigUint::from_bytes_be(&digest) % n
}

pub fn blind(value: &BigUint, e: &BigUint, n: &BigUint) -> (BigUint, BigUint) {
    let mut rng = thread_rng();
    let one = BigUint::one();
    let factor = loop {
        let candidate = rng.gen_biguint_range(&BigUint::from(2u32), n);
        if modular_inverse(&candidate, n) != one || candidate != one {
            break candidate;
        }
    };
    let blinded = (value * factor.modpow(e, n)) % n;
    (blinded, factor)
}

pub fn unblind(signed: &BigUint, factor: &BigUint, n: &BigUint) -> BigUint {
    (signed * modular_inverse(factor, n)) % n
}

pub fn token(value: &BigUint, d: &BigUint, n: &BigUint) -> BigUint {
    value.modpow(d, n)
}

pub fn to_hex(value: &BigUint) -> String {
    value.to_str_radix(16)
}

pub fn from_hex(text: &str) -> BigUint {
    BigUint::parse_bytes(text.as_bytes(), 16).unwrap_or_else(BigUint::zero)
}

/// Signed round trip used by the unit test below: blinding, signing, unblinding must return the
/// same token the holder computes. If this fails, nothing else in the flow can be trusted.
pub fn round_trip_works() -> bool {
    let key = RsaKey::generate();
    let value = feature_hash("skill:design", &key.n);
    let (blinded, factor) = blind(&value, &key.e, &key.n);
    let signed = token(&blinded, &key.d, &key.n);
    let unblinded = unblind(&signed, &factor, &key.n);
    unblinded == token(&value, &key.d, &key.n)
}
