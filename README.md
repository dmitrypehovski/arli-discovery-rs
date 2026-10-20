# ARLI Discovery Extension, second implementation

A standard lives or dies on a question that no amount of argument settles: can somebody else
implement the text from the text? This is that somebody else. The implementation here was written
in Rust against the normative document, with the closed lists transcribed from the document rather
than copied from the reference implementation, and the reference conformance suite is the judge.

## Where it stands

- The reference suite has 30 checks over 26 methods. This implementation passes all 30
  (`result: conformant`), run against two instances of this binary on 2026-10-20.
- The evidence envelopes, the card signature, the opening rules, the turn grammar, the witness step
  that lets two machines negotiate, the registry, retention, claim relay and the blind-RSA matching
  flow are all implemented here.
- Extension 1.2.0. This implementation is what the network test drives as the counterparty: a Python
  service connects this agent by its address, verifies its card, and matches against it over the
  wire, with each side recording the other's turns by witness.
- Claim issuance is deliberately absent, exactly as in the reference: issuing verified statements
  about other people's features is a legal decision, not a code decision. The implementation relays
  and verifies statements made by others and issues none of its own.

## Two implementations, one client, one measurement

The same client drives both implementations, which is itself the claim: if the surface were not the
same, one client could not talk to both. What follows is one full matching exchange (keys, blind,
sign, finish, record) on one machine, local ports, medians of three runs, the same 2048-bit modulus
on both sides, and the same features on both sides. Seconds, not opinions:

    features per side | Python reference | this implementation | ratio
                    8 |           517 ms |              303 ms |  1.5x
                   32 |          1630 ms |              524 ms |  3.1x
                   64 |          2805 ms |              744 ms |  3.8x

Both sides matched the same features at every size, so the comparison is of the same work rather
than of two different answers.

Bounds that belong next to those numbers. One machine, local loopback, no network. The Rust
arithmetic uses `num-bigint` rather than a tuned bignum library, and the modulus generation per
session is included in both columns. An earlier measurement in this project reported a much larger
gap (up to 33x); it was thrown away because it had been taken with a 256-bit modulus here against
2048 bits in the reference, which buys speed with the entire promise of the scheme.

## Building and running

    cargo build --release
    ./target/release/arli-discovery-rs --port 8861 --name my-agent --features "skill:design,city:sf"

The agent answers on `/.well-known/agent-card.json`, `/.well-known/arli-capabilities.json` and
`/a2a/rpc`. To judge it with the reference kit:

    python -m arli_engine.conformance --target http://127.0.0.1:8861 --holder http://127.0.0.1:8862

## What the second implementation found in the first

Our card signatures were DER-encoded. JWS ES256 defines the signature value as the raw R||S pair,
64 bytes, so a third party verifying our cards by the JWS rules would have rejected them while our
own verifier accepted them. The cause is worth naming: card verification lived in two places, and
the two agreed with each other rather than with the text. Fixed in the reference, and the check now
refuses a DER signature with a reason that says why.

Licence: Apache-2.0. The name ARLI and any conformance mark are not granted by this licence.
