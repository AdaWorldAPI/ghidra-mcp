//! PKCE — Proof Key for Code Exchange (RFC 7636).
//!
//! # Why this module exists at all
//!
//! The Python reference implementation (`ada-oauth2-fastmcp`) has the right
//! OAuth2 *shape* — RFC 8414 discovery, `/oauth/authorize`, `/oauth/token`,
//! `authorization_code` + `refresh_token` grants — and **no PKCE**. A grep
//! for `code_challenge` across that repo returns nothing.
//!
//! That is not a nicety to add later. An MCP client is a **public client**:
//! it cannot keep a client secret, because the secret would have to ship
//! with it. For public clients PKCE is the *only* thing binding the
//! authorization code to the party that requested it. Without it, anyone who
//! intercepts a code — from a redirect URI, a log, a referrer header, a
//! malicious app registered for the same custom scheme — can redeem it.
//!
//! RFC 9700 (Best Current Practice for OAuth 2.0 Security, 2025) makes PKCE
//! mandatory for authorization-code flows, and the MCP authorization
//! specification requires it. This is table stakes, not hardening.
//!
//! # What is deliberately NOT supported
//!
//! `plain` is a legal `code_challenge_method` in RFC 7636 §4.2 and this
//! module **rejects it**. `plain` sends the verifier itself as the
//! challenge, so an attacker who can read the authorization request learns
//! everything needed to redeem the code — it defends against nothing that
//! matters here. RFC 7636 §4.2 itself says clients MUST use S256 when they
//! can, and every MCP client can (SHA-256 is universally available).
//!
//! Accepting `plain` "for compatibility" would mean an attacker can DOWNGRADE
//! to it simply by asking, which is strictly worse than not implementing
//! PKCE at all — it looks protected and is not.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The only challenge method this server accepts. See the module docs for
/// why `plain` is refused rather than merely discouraged.
pub const METHOD_S256: &str = "S256";

/// RFC 7636 §4.1: the verifier is 43–128 characters of unreserved ASCII.
pub const VERIFIER_MIN_LEN: usize = 43;
/// RFC 7636 §4.1 upper bound.
pub const VERIFIER_MAX_LEN: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PkceError {
    #[error("code_challenge_method {0:?} is not supported; only S256 is accepted")]
    UnsupportedMethod(String),
    #[error("code_verifier length {0} is outside the RFC 7636 range 43..=128")]
    VerifierLength(usize),
    #[error("code_verifier contains a character outside the RFC 7636 unreserved set")]
    VerifierCharset,
    #[error("code_verifier does not match the code_challenge")]
    Mismatch,
    #[error("this authorization code was issued without a code_challenge")]
    ChallengeMissing,
}

/// RFC 7636 §4.1 unreserved set: `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
#[inline]
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Validate a `code_verifier` against RFC 7636 §4.1 before it is used.
///
/// Length and charset are checked *first* and separately from the hash
/// comparison, so a malformed verifier is rejected as malformed rather than
/// silently failing the digest check — the two are different bugs and a
/// caller debugging one should not see the other's error.
pub fn validate_verifier(verifier: &str) -> Result<(), PkceError> {
    let n = verifier.len();
    if !(VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&n) {
        return Err(PkceError::VerifierLength(n));
    }
    if !verifier.bytes().all(is_unreserved) {
        return Err(PkceError::VerifierCharset);
    }
    Ok(())
}

/// Derive the S256 challenge for a verifier:
/// `BASE64URL-ENCODE(SHA256(ASCII(verifier)))`, **without** padding.
///
/// The unpadded encoding is required, not cosmetic: RFC 7636 §4.2 specifies
/// base64url *without* padding, so a padded encoding produces a challenge
/// that will never match a conformant client's.
pub fn derive_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Verify a presented `code_verifier` against the `code_challenge` recorded
/// when the authorization code was issued.
///
/// `stored_challenge` is `None` when the authorization request carried no
/// challenge. That is an ERROR here, not a pass: a server that treats a
/// missing challenge as "PKCE not required for this code" hands an attacker
/// a downgrade — omit the challenge, skip the proof. The check belongs at
/// issuance too, but failing closed here means a single missed guard cannot
/// open the flow.
pub fn verify(
    stored_challenge: Option<&str>,
    method: &str,
    verifier: &str,
) -> Result<(), PkceError> {
    if method != METHOD_S256 {
        return Err(PkceError::UnsupportedMethod(method.to_owned()));
    }
    let expected = stored_challenge.ok_or(PkceError::ChallengeMissing)?;
    validate_verifier(verifier)?;

    let derived = derive_challenge(verifier);

    // Constant-time. The challenge is not a secret in the way a token is,
    // but the comparison is on the critical path of code redemption and a
    // byte-at-a-time early exit is free information about a value the
    // attacker is trying to forge. The Java side already compares its bearer
    // token in constant time; the Rust side must not be the weak half.
    if derived.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        Err(PkceError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B — the specification's own worked example.
    ///
    /// This is the anchor that proves the implementation is interoperable
    /// rather than merely self-consistent: a wrong-but-consistent
    /// implementation (padded base64, hex, SHA-512) passes every round-trip
    /// test in this file and fails this one.
    #[test]
    fn rfc7636_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(derive_challenge(verifier), expected);
        assert_eq!(verify(Some(expected), METHOD_S256, verifier), Ok(()));
    }

    #[test]
    fn a_wrong_verifier_is_rejected() {
        let good = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let bad = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXA";
        let challenge = derive_challenge(good);
        // Anti-vacuity: the two verifiers must both be VALID, so the
        // rejection is the digest check and not a length/charset guard.
        assert!(validate_verifier(good).is_ok());
        assert!(validate_verifier(bad).is_ok());
        assert_eq!(
            verify(Some(&challenge), METHOD_S256, bad),
            Err(PkceError::Mismatch)
        );
    }

    /// The downgrade this module exists to refuse.
    #[test]
    fn plain_method_is_refused_even_when_it_would_match() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // Under `plain` the challenge IS the verifier, so this would succeed
        // on a server that accepted the method. It must not.
        assert_eq!(
            verify(Some(verifier), "plain", verifier),
            Err(PkceError::UnsupportedMethod("plain".into()))
        );
    }

    /// The other downgrade: omit the challenge, skip the proof.
    #[test]
    fn a_code_issued_without_a_challenge_cannot_be_redeemed() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            verify(None, METHOD_S256, verifier),
            Err(PkceError::ChallengeMissing)
        );
    }

    #[test]
    fn verifier_length_bounds_are_enforced_two_sided() {
        let short = "a".repeat(VERIFIER_MIN_LEN - 1);
        let min = "a".repeat(VERIFIER_MIN_LEN);
        let max = "a".repeat(VERIFIER_MAX_LEN);
        let long = "a".repeat(VERIFIER_MAX_LEN + 1);
        assert_eq!(
            validate_verifier(&short),
            Err(PkceError::VerifierLength(VERIFIER_MIN_LEN - 1))
        );
        assert!(validate_verifier(&min).is_ok(), "43 is legal");
        assert!(validate_verifier(&max).is_ok(), "128 is legal");
        assert_eq!(
            validate_verifier(&long),
            Err(PkceError::VerifierLength(VERIFIER_MAX_LEN + 1))
        );
    }

    #[test]
    fn charset_is_enforced_and_the_unreserved_set_is_admitted() {
        // A legal verifier using every non-alphanumeric unreserved char.
        let ok = format!("-._~{}", "a".repeat(VERIFIER_MIN_LEN - 4));
        assert!(validate_verifier(&ok).is_ok());
        // `+` and `/` are base64 chars but NOT in the unreserved set — the
        // classic mistake of validating against the wrong alphabet.
        let bad = format!("+/{}", "a".repeat(VERIFIER_MIN_LEN - 2));
        assert_eq!(validate_verifier(&bad), Err(PkceError::VerifierCharset));
    }

    /// The challenge must be UNPADDED base64url. A padded encoder is the
    /// single most likely silent incompatibility, and it would pass a
    /// round-trip test written against itself.
    #[test]
    fn challenge_encoding_is_unpadded_base64url() {
        let c = derive_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert!(!c.contains('='), "padding must not be emitted");
        assert!(!c.contains('+') && !c.contains('/'), "must be url-safe");
        // SHA-256 is 32 bytes -> ceil(32/3)*4 = 44 with padding, 43 without.
        assert_eq!(c.len(), 43);
    }
}
