//! TLS 1.2 cipher suite registrations + PRF.
//!
//! Four FIPS-approved GCM cipher suites:
//! - `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
//! - `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
//! - `ECDHE_RSA_WITH_AES_128_GCM_SHA256`
//! - `ECDHE_RSA_WITH_AES_256_GCM_SHA384`
//!
//! ## Wire format (RFC 5288)
//!
//! Each record body is `explicit_nonce(8) || ciphertext || tag(16)`. The
//! full AEAD nonce is `implicit_iv(4) || explicit_nonce(8)`, where the
//! implicit IV comes from the TLS 1.2 key_block (`fixed_iv_len = 4`) and the
//! explicit nonce is the (per-record) 8-byte counter sent in the clear.
//!
//! AAD = `seq_num(8) || ContentType(1) || ProtocolVersion(2) || Length(2)`
//! (constructed via [`make_tls12_aad`]). Length is plaintext length, NOT
//! including the explicit nonce or tag.

use rustls::ConnectionTrafficSecrets;
use rustls::crypto::ActiveKeyExchange;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::crypto::tls12::{Prf, PrfUsingHmac};
use zeroize::Zeroizing;

use crate::aead;
use crate::hmac::{HMAC_SHA256, HMAC_SHA384};

const EXPLICIT_NONCE_LEN: usize = 8;
const IMPLICIT_IV_LEN: usize = 4;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = aead::TAG_LEN;

// =========================================================================
// AEAD algorithm wrappers
// =========================================================================

#[derive(Debug)]
pub struct Aes128Gcm;
#[derive(Debug)]
pub struct Aes256Gcm;

impl Tls12AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        // RFC 5288 §3 / RFC 5246 §6.2.3.3: explicit_nonce must be unique
        // per (key, fixed_iv) pair. Two RFC-compliant constructions are
        // common in the ecosystem:
        //
        // 1. `extra ^ seq.to_be_bytes()` — XOR the rustls-provided
        //    per-connection 8-byte random `extra` with the big-endian
        //    sequence number. This is what rustls's own aws-lc-rs and
        //    ring providers do; the per-connection random adds defense
        //    against cross-connection nonce-reuse if a key-extraction
        //    state-corruption attack ever weakened the seq counter.
        // 2. `seq.to_be_bytes()` alone — also unique-per-record, but
        //    predictable and slightly weaker against the same attack.
        //
        // We adopt (1) to match upstream rustls behaviour and audit
        // posture. The decrypter side does not care which construction
        // the peer used — it reads explicit_nonce verbatim from the
        // wire and trusts GCM authentication to catch any disagreement.
        make_encrypter(key, iv, extra)
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        make_decrypter(key, iv)
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: aead::AES128_KEY_LEN,
            fixed_iv_len: IMPLICIT_IV_LEN,
            explicit_nonce_len: EXPLICIT_NONCE_LEN,
        }
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm {
            key,
            iv: build_iv(iv, explicit),
        })
    }
    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

impl Tls12AeadAlgorithm for Aes256Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        // See `Aes128Gcm::encrypter` for the explicit-nonce policy.
        make_encrypter(key, iv, extra)
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        make_decrypter(key, iv)
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: aead::AES256_KEY_LEN,
            fixed_iv_len: IMPLICIT_IV_LEN,
            explicit_nonce_len: EXPLICIT_NONCE_LEN,
        }
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv: build_iv(iv, explicit),
        })
    }
    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

fn build_iv(iv: &[u8], explicit: &[u8]) -> rustls::crypto::cipher::Iv {
    // Fail-loud in release: a wrong-length IV from rustls would mean a
    // serious upstream contract break, and the silent panic via
    // `copy_from_slice` later is harder to diagnose than an explicit one.
    assert_eq!(
        iv.len(),
        IMPLICIT_IV_LEN,
        "TLS 1.2 implicit IV must be {IMPLICIT_IV_LEN} bytes"
    );
    assert_eq!(
        explicit.len(),
        EXPLICIT_NONCE_LEN,
        "TLS 1.2 explicit nonce must be {EXPLICIT_NONCE_LEN} bytes"
    );
    let mut full = [0u8; NONCE_LEN];
    full[..IMPLICIT_IV_LEN].copy_from_slice(iv);
    full[IMPLICIT_IV_LEN..].copy_from_slice(explicit);
    rustls::crypto::cipher::Iv::copy(&full)
}

// rustls-API note (A-1, comment-only per review): the `extra` parameter
// here is the 8-byte per-connection random rustls passes through from
// the TLS 1.2 key_block (RFC 5246 §6.3) for use in deriving the
// explicit_nonce. We follow the aws-lc-rs / ring providers' construction
// (`extra XOR seq.to_be_bytes()`) verbatim; this is *not* a rustls trait
// contract — rustls treats `extra` as opaque per-connection material.
// If a future rustls release changes the semantics of `extra` (e.g. to
// "use as full nonce" rather than "salt to XOR with seq") this function
// will silently produce nonces that don't match peers, surfacing as
// `DecryptError` in handshake_smoke. The regression test
// `tls12_explicit_nonce_is_extra_xor_seq` pins the current wire shape.
fn make_encrypter(key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
    assert_eq!(
        iv.len(),
        IMPLICIT_IV_LEN,
        "TLS 1.2 implicit IV must be {IMPLICIT_IV_LEN} bytes"
    );
    assert_eq!(
        extra.len(),
        EXPLICIT_NONCE_LEN,
        "TLS 1.2 explicit nonce material must be {EXPLICIT_NONCE_LEN} bytes"
    );
    // Pre-assemble the 12-byte full nonce template: implicit_iv(4) || extra(8).
    // On each encrypt we XOR `seq.to_be_bytes()` into the trailing 8 bytes,
    // matching rustls's aws-lc-rs / ring providers.
    let mut full_iv = [0u8; NONCE_LEN];
    full_iv[..IMPLICIT_IV_LEN].copy_from_slice(iv);
    full_iv[IMPLICIT_IV_LEN..].copy_from_slice(extra);
    Box::new(Tls12Encrypter {
        key: Zeroizing::new(key.as_ref().to_vec()),
        full_iv,
    })
}

fn make_decrypter(key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
    assert_eq!(
        iv.len(),
        IMPLICIT_IV_LEN,
        "TLS 1.2 implicit IV must be {IMPLICIT_IV_LEN} bytes"
    );
    let mut implicit = [0u8; IMPLICIT_IV_LEN];
    implicit.copy_from_slice(iv);
    Box::new(Tls12Decrypter {
        key: Zeroizing::new(key.as_ref().to_vec()),
        implicit_iv: implicit,
    })
}

// =========================================================================
// Encrypter / Decrypter
// =========================================================================

struct Tls12Encrypter {
    /// AEAD session key. `Zeroizing` wipes the bytes on drop.
    key: Zeroizing<Vec<u8>>,
    /// Pre-assembled 12-byte nonce template: `implicit_iv(4) || extra(8)`.
    /// Each `encrypt` call XORs `seq.to_be_bytes()` into the trailing
    /// 8 bytes to derive the per-record nonce (see `Tls12AeadAlgorithm::encrypter`
    /// comment for rationale).
    full_iv: [u8; NONCE_LEN],
}

impl MessageEncrypter for Tls12Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let pt_len = msg.payload.len();
        // Derive the per-record nonce: implicit_iv(4) is left untouched;
        // the trailing 8 bytes are `extra XOR seq.to_be_bytes()`. Matches
        // rustls's aws-lc-rs / ring TLS 1.2 nonce construction.
        let mut nonce = self.full_iv;
        let seq_be = seq.to_be_bytes();
        for i in 0..EXPLICIT_NONCE_LEN {
            nonce[IMPLICIT_IV_LEN + i] ^= seq_be[i];
        }

        let aad = make_tls12_aad(seq, msg.typ, msg.version, pt_len);

        // `Zeroizing` wipes the plaintext on drop after the encrypt call.
        let mut pt: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(pt_len));
        msg.payload.copy_to_vec(&mut pt);

        let mut ct = vec![0u8; pt_len];
        let tag = aead::encrypt(&self.key, &nonce, aad.as_ref(), &pt, &mut ct)
            .map_err(|e| rustls::Error::General(format!("AES-GCM encrypt: {e}")))?;

        // Wire: explicit_nonce(8) || ciphertext || tag(16).
        let mut payload = PrefixedPayload::with_capacity(EXPLICIT_NONCE_LEN + ct.len() + TAG_LEN);
        payload.extend_from_slice(&nonce[IMPLICIT_IV_LEN..]); // explicit
        payload.extend_from_slice(&ct);
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        EXPLICIT_NONCE_LEN + payload_len + TAG_LEN
    }
}

struct Tls12Decrypter {
    /// AEAD session key. `Zeroizing` wipes the bytes on drop.
    key: Zeroizing<Vec<u8>>,
    implicit_iv: [u8; IMPLICIT_IV_LEN],
}

impl MessageDecrypter for Tls12Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_len = msg.payload.len();
        if payload_len < EXPLICIT_NONCE_LEN + TAG_LEN {
            return Err(rustls::Error::DecryptError);
        }
        let ct_len = payload_len - EXPLICIT_NONCE_LEN - TAG_LEN;

        // Split: explicit_nonce(8) | ciphertext(ct_len) | tag(16).
        let payload = &mut msg.payload[..];
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..IMPLICIT_IV_LEN].copy_from_slice(&self.implicit_iv);
        nonce[IMPLICIT_IV_LEN..].copy_from_slice(&payload[..EXPLICIT_NONCE_LEN]);

        let aad = make_tls12_aad(seq, msg.typ, msg.version, ct_len);

        let ct_start = EXPLICIT_NONCE_LEN;
        let tag_start = payload_len - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&payload[tag_start..]);

        // `Zeroizing` wipes the decrypted plaintext from this temp on drop.
        let mut pt: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; ct_len]);
        aead::decrypt(
            &self.key,
            &nonce,
            aad.as_ref(),
            &payload[ct_start..tag_start],
            &mut pt,
            &tag,
        )
        .map_err(|_| rustls::Error::DecryptError)?;

        // Shift the plaintext to the front of the payload, truncate.
        payload[..ct_len].copy_from_slice(&pt);
        msg.payload.truncate(ct_len);
        Ok(msg.into_plain_message())
    }
}

// =========================================================================
// Public statics
// =========================================================================

pub static AES_128_GCM: Aes128Gcm = Aes128Gcm;
pub static AES_256_GCM: Aes256Gcm = Aes256Gcm;

// TLS 1.2 PRF (RFC 5246 §5) is a P_hash construction over HMAC. rustls
// provides `PrfUsingHmac` as a generic wrapper, but its `fips()` returns
// `false` because rustls intentionally does not treat HMAC-composed PRF
// as FIPS-validated.
//
// Compare with the rustls aws_lc_rs provider: when compiled with
// `--features fips` it bypasses `PrfUsingHmac` entirely and uses a
// dedicated `Tls12Prf` backed by aws-lc-fips's separately CAVS-validated
// `tls_prf::Algorithm` primitive (NIST SP 800-135 §4.2.2 Component
// Validation List "TlsKdfPrf"). That is what makes their PRF FIPS-claim
// auditable.
//
// Apple corecrypto **does not** expose a CAVS-listed dedicated TLS PRF
// primitive — Security.framework / CommonCrypto only ship the HMAC and
// hash primitives. We therefore use `PrfUsingHmac` honestly: it is
// constructed from FIPS-validated HMAC primitives, but the PRF as a whole
// is NOT itself CAVS-validated. We do NOT override `fips()` — it returns
// the default `false`.
//
// Practical consequence: `Tls12CipherSuite::fips()` is `false` for every
// TLS 1.2 cipher suite this provider exposes, so `ServerConfig::fips()` /
// `ClientConfig::fips()` is `true` ONLY when the negotiated protocol is
// TLS 1.3 (where HKDF is the Approved KDF per SP 800-56C and the chain
// is HMAC-anchored without a separate PRF step). FIPS-conscious callers
// must restrict their config to TLS 1.3 — see ADR 0004 "FIPS posture".

/// TLS 1.2 PRF using HMAC-SHA-256.
///
/// Not FIPS-validated as a composite primitive (see module comment).
#[derive(Debug)]
pub struct PrfSha256;
/// TLS 1.2 PRF using HMAC-SHA-384.
///
/// Not FIPS-validated as a composite primitive (see module comment).
#[derive(Debug)]
pub struct PrfSha384;

pub static PRF_SHA256: PrfSha256 = PrfSha256;
pub static PRF_SHA384: PrfSha384 = PrfSha384;

impl Prf for PrfSha256 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        PrfUsingHmac(&HMAC_SHA256).for_key_exchange(output, kx, peer_pub_key, label, seed)
    }
    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        PrfUsingHmac(&HMAC_SHA256).for_secret(output, secret, label, seed)
    }
    // Intentionally NOT overridden — default `false`. See module comment.
}

impl Prf for PrfSha384 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        PrfUsingHmac(&HMAC_SHA384).for_key_exchange(output, kx, peer_pub_key, label, seed)
    }
    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        PrfUsingHmac(&HMAC_SHA384).for_secret(output, secret, label, seed)
    }
    // Intentionally NOT overridden — default `false`. See module comment.
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::cipher::OutboundChunks;
    use rustls::{ContentType, ProtocolVersion};

    fn aead_key_256() -> AeadKey {
        // See tls13.rs tests — public API only constructs 32-byte AeadKey,
        // so AES-128 unit-tests aren't expressible here. AES-128 is
        // exercised end-to-end by handshake_smoke.
        AeadKey::from([0x99u8; 32])
    }
    fn implicit_iv() -> [u8; 4] {
        [0x77u8; 4]
    }

    /// TLS 1.2 record encrypt → decrypt roundtrip for AES-256-GCM with the
    /// explicit-nonce wire format. Catches: wrong AAD construction (TLS 1.2
    /// uses seq||type||version||length, different from TLS 1.3), wrong
    /// nonce assembly (implicit_iv(4) || explicit_seq(8)), broken extraction
    /// of explicit-nonce prefix on decrypt.
    #[test]
    fn aes256_gcm_record_roundtrip() {
        let mut enc =
            Tls12AeadAlgorithm::encrypter(&AES_256_GCM, aead_key_256(), &implicit_iv(), &[0u8; 8]);
        let mut dec = Tls12AeadAlgorithm::decrypter(&AES_256_GCM, aead_key_256(), &implicit_iv());

        let payload: &[u8] = b"tls 1.2 application data";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 100).expect("encrypt");

        let wire = opaque.encode();
        let mut body = wire[5..].to_vec(); // strip 5-byte record header

        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            body.as_mut_slice(),
        );
        let plain = dec.decrypt(inbound, 100).expect("decrypt");
        assert_eq!(plain.payload, payload);
        assert_eq!(plain.typ, ContentType::ApplicationData);
    }

    /// Wrong sequence number on decrypt must fail — the seq feeds both the
    /// nonce (via explicit prefix on wire == seq on rustls side) and the AAD.
    #[test]
    fn aes256_gcm_wrong_seq_fails() {
        let mut enc =
            Tls12AeadAlgorithm::encrypter(&AES_256_GCM, aead_key_256(), &implicit_iv(), &[0u8; 8]);
        let mut dec = Tls12AeadAlgorithm::decrypter(&AES_256_GCM, aead_key_256(), &implicit_iv());

        let payload: &[u8] = b"x";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 11).expect("encrypt");
        let wire = opaque.encode();
        let mut body = wire[5..].to_vec();
        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            body.as_mut_slice(),
        );
        // seq=99 ≠ 11 → AAD mismatch → tag mismatch.
        assert!(dec.decrypt(inbound, 99).is_err());
    }

    /// `encrypted_payload_len(N)` exactly equals N + 8 (explicit nonce) +
    /// 16 (tag). Catches drift between this accessor and `encrypt` output.
    #[test]
    fn encrypted_payload_len_matches_encrypt_output() {
        let mut enc =
            Tls12AeadAlgorithm::encrypter(&AES_256_GCM, aead_key_256(), &implicit_iv(), &[0u8; 8]);
        let payload: &[u8] = b"abcdef";

        let predicted = enc.encrypted_payload_len(payload.len());

        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 1).expect("encrypt");
        let body_len = opaque.encode().len() - 5;

        assert_eq!(predicted, body_len);
        assert_eq!(predicted, payload.len() + EXPLICIT_NONCE_LEN + TAG_LEN);
    }

    /// `key_block_shape` contract: AES-128 / AES-256 differ only in
    /// `enc_key_len`; both use the same 4-byte implicit IV + 8-byte
    /// explicit nonce. rustls derives the TLS 1.2 key_block layout from
    /// these numbers.
    #[test]
    fn key_block_shape_contract() {
        let s128 = Tls12AeadAlgorithm::key_block_shape(&AES_128_GCM);
        let s256 = Tls12AeadAlgorithm::key_block_shape(&AES_256_GCM);
        assert_eq!(s128.enc_key_len, 16);
        assert_eq!(s256.enc_key_len, 32);
        assert_eq!(s128.fixed_iv_len, IMPLICIT_IV_LEN);
        assert_eq!(s256.fixed_iv_len, IMPLICIT_IV_LEN);
        assert_eq!(s128.explicit_nonce_len, EXPLICIT_NONCE_LEN);
        assert_eq!(s256.explicit_nonce_len, EXPLICIT_NONCE_LEN);
    }

    /// `extract_keys` returns the right `ConnectionTrafficSecrets` variant
    /// for both AES widths. Required by callers exporting keys.
    #[test]
    fn extract_keys_aes128_variant() {
        let secrets = Tls12AeadAlgorithm::extract_keys(
            &AES_128_GCM,
            aead_key_256(),
            &implicit_iv(),
            &[0u8; 8],
        )
        .expect("extract");
        assert!(matches!(
            secrets,
            rustls::ConnectionTrafficSecrets::Aes128Gcm { .. }
        ));
    }

    #[test]
    fn extract_keys_aes256_variant() {
        let secrets = Tls12AeadAlgorithm::extract_keys(
            &AES_256_GCM,
            aead_key_256(),
            &implicit_iv(),
            &[0u8; 8],
        )
        .expect("extract");
        assert!(matches!(
            secrets,
            rustls::ConnectionTrafficSecrets::Aes256Gcm { .. }
        ));
    }

    /// FIPS-claim contract for both AEAD variants.
    #[test]
    fn aead_fips_contract() {
        assert!(Tls12AeadAlgorithm::fips(&AES_128_GCM));
        assert!(Tls12AeadAlgorithm::fips(&AES_256_GCM));
    }

    /// PRF FIPS contract: our `Prf` impls do NOT override `fips()`, so
    /// they inherit the trait default `false`. This is the honest stance —
    /// TLS 1.2 PRF is a generic HMAC-P_hash composition; corecrypto does
    /// not expose a separately CAVS-validated TLS PRF primitive (unlike
    /// aws-lc-fips, which has one). A regression that re-introduces a
    /// `fips() = true` override here would silently re-claim FIPS for
    /// TLS 1.2 cipher suites and poison `ServerConfig::fips()` /
    /// `ClientConfig::fips()` for any TLS-1.2-negotiated connection.
    #[test]
    fn prf_fips_contract_is_intentionally_false() {
        assert!(
            !PRF_SHA256.fips(),
            "PRF must NOT claim FIPS -- generic HMAC P_hash is not CAVS-validated"
        );
        assert!(!PRF_SHA384.fips(), "same as PRF_SHA256");
    }

    /// **M-2 invariant.** Each TLS 1.2 cipher suite's `fips()` MUST be
    /// `false` regardless of its AEAD's individual `fips()`. rustls's
    /// `Tls12CipherSuite::fips()` is the AND of `hash.fips() &&
    /// aead.fips() && prf.fips()`; our PRF's `false` carries the whole
    /// suite to `false`. If a future refactor accidentally overrides
    /// `PrfUsingHmac::fips()` to `true` (or rustls upstream changes its
    /// default), this test surfaces the regression at the cipher-suite
    /// layer rather than letting it propagate silently to
    /// `default_provider().fips() = true` on TLS 1.2 paths.
    #[test]
    fn tls12_cipher_suite_fips_is_false_due_to_prf() {
        use crate::provider::{
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        };
        for cs in [
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ] {
            let suite = cs.suite();
            assert!(
                !cs.fips(),
                "TLS 1.2 cipher suite {suite:?} unexpectedly claims FIPS -- PRF gap should keep it false"
            );
        }
    }

    /// **M-4 regression (explicit-nonce policy).** With a non-zero `extra`,
    /// the explicit nonce on the wire must be `extra XOR seq.to_be_bytes()`,
    /// matching rustls's aws-lc-rs and ring TLS 1.2 nonce construction.
    /// The wire bytes are the first 8 of the encrypted body (record-header
    /// stripped).
    #[test]
    fn tls12_explicit_nonce_is_extra_xor_seq() {
        let extra: [u8; 8] = [0xa5, 0x5a, 0xff, 0x00, 0x12, 0x34, 0x56, 0x78];
        let mut enc =
            Tls12AeadAlgorithm::encrypter(&AES_256_GCM, aead_key_256(), &implicit_iv(), &extra);
        let payload: &[u8] = b"x";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let seq: u64 = 0x0102_0304_0506_0708;
        let opaque = enc.encrypt(msg, seq).expect("encrypt");
        let wire = opaque.encode();
        let body = &wire[5..]; // strip 5-byte record header

        let mut expected_explicit = extra;
        let seq_be = seq.to_be_bytes();
        for i in 0..8 {
            expected_explicit[i] ^= seq_be[i];
        }
        assert_eq!(
            &body[..EXPLICIT_NONCE_LEN],
            &expected_explicit,
            "explicit nonce must be extra XOR seq"
        );

        // Two distinct `extra` values must produce distinct explicit
        // nonces for the same seq — defends against a regression that
        // accidentally ignores `extra`.
        let mut enc2 =
            Tls12AeadAlgorithm::encrypter(&AES_256_GCM, aead_key_256(), &implicit_iv(), &[0u8; 8]);
        let opaque2 = enc2
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: OutboundChunks::Single(payload),
                },
                seq,
            )
            .expect("encrypt");
        let wire2 = opaque2.encode();
        assert_ne!(
            &wire[5..5 + EXPLICIT_NONCE_LEN],
            &wire2[5..5 + EXPLICIT_NONCE_LEN],
            "distinct `extra` must yield distinct explicit nonces"
        );
    }

    /// Decryption of a too-short payload (< explicit_nonce + tag) must
    /// error rather than panic — boundary safety against malformed records.
    #[test]
    fn aes256_gcm_too_short_payload_errors() {
        let mut dec = Tls12AeadAlgorithm::decrypter(&AES_256_GCM, aead_key_256(), &implicit_iv());
        let mut buf = [0u8; 10]; // < EXPLICIT_NONCE_LEN + TAG_LEN
        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut buf[..],
        );
        assert!(dec.decrypt(inbound, 0).is_err());
    }

    /// C-3 regression: a wrong-length implicit IV must surface as an
    /// explicit panic with a descriptive message, not a silent
    /// `copy_from_slice` panic deeper in the call stack. The contract is
    /// that rustls always passes 4-byte implicit IVs; if that ever
    /// breaks, the error should be obvious to debug.
    #[test]
    #[should_panic(expected = "TLS 1.2 implicit IV must be 4 bytes")]
    fn build_iv_panics_on_wrong_iv_length() {
        let _ = build_iv(&[0u8; 3], &[0u8; 8]);
    }

    #[test]
    #[should_panic(expected = "TLS 1.2 explicit nonce must be 8 bytes")]
    fn build_iv_panics_on_wrong_explicit_length() {
        let _ = build_iv(&[0u8; 4], &[0u8; 7]);
    }

    #[test]
    #[should_panic(expected = "TLS 1.2 implicit IV must be 4 bytes")]
    fn make_encrypter_panics_on_wrong_iv_length() {
        let _ = make_encrypter(AeadKey::from([0u8; 32]), &[0u8; 5], &[0u8; 8]);
    }

    /// PRF wire-correctness regression. Constructs the P_hash reference
    /// output by hand per RFC 5246 §5:
    ///
    ///   A(0) = seed (where "seed" here = label || actual_seed)
    ///   A(i) = HMAC(secret, A(i-1))
    ///   P_hash output = HMAC(secret, A(1) || seed) ||
    ///                   HMAC(secret, A(2) || seed) || ...
    ///   PRF(secret, label, actual_seed) = P_hash(secret, label || actual_seed)
    ///
    /// then compares to our `PRF_SHA256::for_secret` output. If a future
    /// refactor breaks the label/seed concatenation order or the A(i)
    /// recurrence, this test fails. Together with the existing HMAC
    /// RFC 4231 KAT tests, this gives end-to-end wire correctness for
    /// our TLS 1.2 PRF construction. (The PRF itself is not CAVS-
    /// validated on macOS — see ADR 0004 — but it MUST still produce
    /// RFC 5246-correct output to interoperate with peers.)
    #[test]
    fn prf_sha256_matches_manual_p_hash_per_rfc5246() {
        use rustls::crypto::hmac::Hmac;

        let secret = b"my-master-secret-bytes";
        let label = b"key expansion";
        let seed = b"server_random || client_random";
        let mut out = [0u8; 96]; // 3 SHA-256 blocks (= 3 P_hash iterations)
        PRF_SHA256.for_secret(&mut out, secret, label, seed);

        // Manual P_hash(secret, label || seed):
        let mac = HMAC_SHA256.with_key(secret);
        let combined_seed: Vec<u8> = label.iter().chain(seed.iter()).copied().collect();

        let mut a_prev = mac.sign(&[&combined_seed]); // A(1) = HMAC(secret, A(0)=seed)
        let mut expected = Vec::<u8>::with_capacity(96);
        for _ in 0..3 {
            // P_hash block = HMAC(secret, A(i) || label || seed)
            let block = mac.sign(&[a_prev.as_ref(), label, seed]);
            expected.extend_from_slice(block.as_ref());
            // A(i+1) = HMAC(secret, A(i))
            a_prev = mac.sign(&[a_prev.as_ref()]);
        }

        assert_eq!(
            out.as_slice(),
            &expected[..96],
            "PRF output diverges from manual P_hash reference — wire-incorrect"
        );
    }

    /// PRF `for_secret`: HMAC-based P_hash must produce deterministic
    /// output. Catches a bug where PRF accidentally uses non-deterministic
    /// state (e.g. uninit memory).
    #[test]
    fn prf_for_secret_is_deterministic() {
        let secret = b"premaster_secret_dummy";
        let label = b"key expansion";
        let seed = b"server_random || client_random";
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        PRF_SHA256.for_secret(&mut a, secret, label, seed);
        PRF_SHA256.for_secret(&mut b, secret, label, seed);
        assert_eq!(a, b);
        // Output must not be all zeros (a broken PRF that returns the
        // initial buffer would).
        assert!(a.iter().any(|&x| x != 0));
    }
}
