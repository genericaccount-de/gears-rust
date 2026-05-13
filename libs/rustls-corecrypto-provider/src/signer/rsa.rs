//! RSA `SigningKey` over Apple corecrypto.
//!
//! Supports RSA-PSS and RSA-PKCS#1 v1.5 with SHA-256 / SHA-384 / SHA-512,
//! parity with [`rustls-cng-crypto`'s `signer/rsa.rs`
//! ](https://docs.rs/rustls-cng-crypto/0.1.2/rustls_cng_crypto/) on the
//! Windows side.
//!
//! ## Key import flow
//!
//! Apple's `SecKeyCreateWithData` accepts **PKCS#1 `RSAPrivateKey` DER**
//! (the inner SEQUENCE) but **rejects PKCS#8** envelopes outright. rustls
//! delivers private keys as `PrivateKeyDer::{Pkcs1, Pkcs8, Sec1}`; here
//! we accept:
//!
//! - `Pkcs1` — pass-through (already the format Apple wants).
//! - `Pkcs8` — unwrap via [`pkcs8::PrivateKeyInfo`], verify `algorithm.oid
//!   == rsaEncryption`, hand `.private_key` (the inner PKCS#1 bytes) to
//!   Apple.
//! - `Sec1` — rejected (EC-only encoding).
//!
//! The unwrap is a structural DER parse only — no cryptographic primitive
//! runs through the `pkcs8` crate, so the FIPS-claim chain-of-trust stays
//! anchored at corecrypto. Apple's
//! `kSecKeyAlgorithmRSASignatureMessage{Pss,Pkcs1v15}Sha{256,384,512}`
//! variants take the raw message and hash + sign inside corecrypto.

use std::sync::Arc;

use rustls::Error;
use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use security_framework::key::{Algorithm, SecKey};
use zeroize::Zeroizing;

use crate::ffi::security::{PrivateKeyKind, import_private_key, seckey_block_size};

/// RSA signature schemes we offer for negotiation, in descending order of
/// preference. Mirrors `rustls-cng-crypto::signer::rsa::RSA_SCHEMES`; the
/// constant is consumed by TLS 1.2 ECDHE_RSA cipher suites to advertise
/// supported `signature_algorithms` extension entries.
///
/// **Ordering rationale (A-3 comment per security review).** PSS is
/// listed before PKCS#1 v1.5 because:
///
/// 1. **TLS 1.3 mandates PSS** for `CertificateVerify` (RFC 8446 §4.2.3).
///    PKCS#1 v1.5 entries are disallowed for TLS 1.3 signing — rustls
///    filters them out of the TLS 1.3 sig_alg negotiation surface — so
///    in TLS 1.3 only the PSS half of this list is reachable.
/// 2. **PSS is the modern provable-security choice** (RSA-PSS has tight
///    reductions to RSA assumption; PKCS#1 v1.5 has a long history of
///    padding-oracle and Bleichenbacher-style attacks at the protocol
///    layer).
/// 3. **TLS 1.2 peer-compat keeps PKCS#1 v1.5** in the list — older
///    endpoints (and some embedded stacks) still negotiate it. Ordering
///    means we *prefer* PSS but accept PKCS#1 v1.5 as fallback when the
///    peer offers nothing else.
///
/// Within each family, SHA-512 → SHA-384 → SHA-256 prefers the larger
/// digest (parity with `rustls-cng-crypto` and `aws-lc-rs`).
pub(crate) static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// RSA private key wrapped as an opaque `SecKey`. The DER bytes used to
/// construct it never leave the local stack — `SecKey` is reference-
/// counted by Apple corecrypto, so the secret material lives inside the
/// FIPS-validated module after `SecKeyCreateWithData` returns.
#[derive(Debug)]
pub(crate) struct RsaSigningKey {
    key: Arc<SecKey>,
}

impl RsaSigningKey {
    /// Construct an `RsaSigningKey` from a rustls `PrivateKeyDer`.
    ///
    /// Returns `Err` on non-RSA input or malformed DER. The error message
    /// is intentionally terse so the dispatcher in
    /// [`super::any_supported_type`] can silently fall through to EC.
    ///
    /// The intermediate PKCS#1 bytes are kept in a [`Zeroizing`] buffer so
    /// the plaintext private material is wiped from heap memory the
    /// moment `import_private_key` finishes (FIPS 140-3 IG 9.5 "no
    /// plaintext CSPs outside the cryptographic boundary").
    pub(crate) fn new(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let pkcs1: Zeroizing<Vec<u8>> = match der {
            PrivateKeyDer::Pkcs1(p) => Zeroizing::new(p.secret_pkcs1_der().to_vec()),
            PrivateKeyDer::Pkcs8(p) => extract_rsa_pkcs1_from_pkcs8(p.secret_pkcs8_der())?,
            PrivateKeyDer::Sec1(_) => {
                return Err(Error::General(
                    "rustls-corecrypto-provider: SEC1 is an EC encoding, not RSA".to_owned(),
                ));
            }
            _ => {
                return Err(Error::General(
                    "rustls-corecrypto-provider: unrecognized PrivateKeyDer variant".to_owned(),
                ));
            }
        };

        let key = import_private_key(&pkcs1, PrivateKeyKind::RsaPkcs1)
            .map_err(|e| Error::General(format!("RSA key import failed: {e}")))?;

        // FIPS-4: enforce minimum modulus size 2048 bits.
        // SecKeyGetBlockSize returns the signature length in bytes, which
        // equals the modulus size in bytes for RSA. NIST FIPS 186-5 §5.1
        // mandates RSA modulus ≥ 2048 bits for signing.
        let modulus_bytes = seckey_block_size(&key);
        if modulus_bytes < 256 {
            return Err(Error::General(format!(
                "RSA key modulus {}-bit is below the FIPS 186-5 minimum of 2048 bits",
                modulus_bytes * 8
            )));
        }

        Ok(Self { key: Arc::new(key) })
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Iterate by *our* preference order, not the peer's — matches what
        // rustls-cng-crypto does and what aws-lc-rs's `RsaSigningKey` does.
        // The peer's `offered` list is a filter, not a ranking.
        RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|scheme| {
                Box::new(RsaSigner {
                    key: Arc::clone(&self.key),
                    scheme: *scheme,
                    algorithm: scheme_to_algorithm(*scheme),
                }) as Box<dyn Signer>
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

struct RsaSigner {
    key: Arc<SecKey>,
    scheme: SignatureScheme,
    algorithm: Algorithm,
}

// `security_framework::key::Algorithm` does not implement `Debug` upstream,
// so the derive macro can't reach this struct. We only need a Debug to
// satisfy rustls's `Signer: Debug` bound; the algorithm is captured
// indirectly via `scheme` for human inspection.
impl std::fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .create_signature(self.algorithm, message)
            .map_err(|e| {
                // Only structured fields — avoid `{e:?}` which includes
                // Apple's localized description.
                Error::General(format!(
                    "RSA sign failed: domain={} code={}",
                    e.domain(),
                    e.code()
                ))
            })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Map a TLS-level `SignatureScheme` to the corresponding Apple corecrypto
/// `SecKeyAlgorithm` (via the `security-framework` enum). The mapping is
/// total over `RSA_SCHEMES`, so callers that picked a scheme from there
/// can rely on the `unreachable!` arm staying unreached.
///
/// **Invariant (covered by `scheme_to_algorithm_total_over_rsa_schemes`
/// test): every entry in `RSA_SCHEMES` must map to a real `Algorithm`,
/// not panic.** A regression that added a new scheme to `RSA_SCHEMES`
/// without extending this `match` would surface as a test failure
/// rather than a runtime panic on the first signing operation.
fn scheme_to_algorithm(scheme: SignatureScheme) -> Algorithm {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256 => Algorithm::RSASignatureMessagePSSSHA256,
        SignatureScheme::RSA_PSS_SHA384 => Algorithm::RSASignatureMessagePSSSHA384,
        SignatureScheme::RSA_PSS_SHA512 => Algorithm::RSASignatureMessagePSSSHA512,
        SignatureScheme::RSA_PKCS1_SHA256 => Algorithm::RSASignatureMessagePKCS1v15SHA256,
        SignatureScheme::RSA_PKCS1_SHA384 => Algorithm::RSASignatureMessagePKCS1v15SHA384,
        SignatureScheme::RSA_PKCS1_SHA512 => Algorithm::RSASignatureMessagePKCS1v15SHA512,
        other => unreachable!(
            "scheme_to_algorithm called with non-RSA scheme {other:?}; \
             choose_scheme should have filtered via RSA_SCHEMES"
        ),
    }
}

/// PKCS#1 RSA OID per RFC 3279 §2.3.1.
const RSA_ENCRYPTION_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Strip a PKCS#8 envelope and return the inner PKCS#1 `RSAPrivateKey`
/// bytes in a [`Zeroizing`] buffer. Rejects PKCS#8 wrappers whose
/// algorithm OID is not rsaEncryption (e.g. an EC key would be rejected
/// here and the dispatcher would then fall through to the EC path).
fn extract_rsa_pkcs1_from_pkcs8(pkcs8_der: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let info = pkcs8::PrivateKeyInfo::try_from(pkcs8_der)
        .map_err(|e| Error::General(format!("PKCS#8 parse failed: {e}")))?;
    if info.algorithm.oid != RSA_ENCRYPTION_OID {
        return Err(Error::General(format!(
            "PKCS#8 algorithm OID is not rsaEncryption: got {}",
            info.algorithm.oid
        )));
    }
    Ok(Zeroizing::new(info.private_key.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{KeyPair, PKCS_RSA_SHA256};
    use rustls::pki_types::pem::PemObject;

    fn gen_rsa_key_der() -> PrivateKeyDer<'static> {
        let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256).expect("rcgen RSA");
        // rcgen produces PKCS#8 PEM by default.
        let pem = key_pair.serialize_pem();
        PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("decode PEM")
    }

    /// Convert a PKCS#8-wrapped key to a `PrivateKeyDer::Pkcs1` by stripping
    /// the outer envelope. Lets us cover the `PrivateKeyDer::Pkcs1` arm in
    /// `RsaSigningKey::new` — rcgen always emits PKCS#8 PEM, so without this
    /// helper that branch stays dark.
    fn pkcs8_to_pkcs1_rsa(pkcs8: &PrivateKeyDer<'_>) -> PrivateKeyDer<'static> {
        use rustls::pki_types::PrivatePkcs1KeyDer;
        let bytes = match pkcs8 {
            PrivateKeyDer::Pkcs8(p) => p.secret_pkcs8_der(),
            other => panic!("expected PKCS#8 input, got {other:?}"),
        };
        let info = pkcs8::PrivateKeyInfo::try_from(bytes).expect("parse PKCS#8");
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(info.private_key.to_vec()))
    }

    /// Loading + immediate usability: after `new`, the key must offer at
    /// least one scheme from `RSA_SCHEMES`. Stronger than a bare load —
    /// catches the case where SecKeyCreateWithData accepts the bytes but
    /// the resulting key cannot be exercised (e.g. wrong KeyClass).
    #[test]
    fn loads_pkcs8_rsa_and_is_usable() {
        let der = gen_rsa_key_der();
        let key = RsaSigningKey::new(&der).expect("load PKCS#8 RSA");
        let signer = key.choose_scheme(RSA_SCHEMES).expect("usable key");
        // Smoke: signer can produce something, not just exist.
        let sig = signer.sign(b"smoke").expect("sign");
        assert!(!sig.is_empty(), "RSA signature must not be empty");
    }

    /// PKCS#1 path: rcgen emits PKCS#8 but some operators ship PKCS#1
    /// directly. Strip the wrapper ourselves and feed bare PKCS#1 to
    /// `new`, then verify a real signature roundtrip — proves the
    /// `PrivateKeyDer::Pkcs1` arm in `new` actually works end-to-end.
    #[test]
    fn loads_pkcs1_rsa_roundtrip() {
        let pkcs8 = gen_rsa_key_der();
        let pkcs1 = pkcs8_to_pkcs1_rsa(&pkcs8);
        let key = RsaSigningKey::new(&pkcs1).expect("load PKCS#1 RSA");
        let signer = key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .expect("scheme");
        let msg = b"pkcs1 roundtrip";
        let sig = signer.sign(msg).expect("sign");
        // Verify through our public-side path to prove wire-format agreement.
        let pub_bytes = key
            .key
            .public_key()
            .expect("pub")
            .external_representation()
            .expect("ext")
            .bytes()
            .to_vec();
        crate::verify::SUPPORTED_SIG_ALGS
            .mapping
            .iter()
            .find(|(s, _)| *s == SignatureScheme::RSA_PSS_SHA256)
            .and_then(|(_, a)| a.first())
            .expect("scheme in mapping")
            .verify_signature(&pub_bytes, msg, &sig)
            .expect("verify PKCS#1-loaded signature");
    }

    /// Wrong-encoding rejection: SEC1 is for EC keys, must be refused by
    /// the RSA constructor with a documented marker string. The dispatcher
    /// in `signer/mod.rs` then falls through to the EC constructor.
    #[test]
    fn rejects_sec1_input_as_not_rsa() {
        use rustls::pki_types::PrivateSec1KeyDer;
        let bogus = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(vec![0u8; 32]));
        match RsaSigningKey::new(&bogus) {
            Err(Error::General(msg)) => assert!(
                msg.contains("SEC1 is an EC encoding"),
                "error must explain SEC1 mismatch, got {msg:?}"
            ),
            other => panic!("expected Error::General for SEC1, got {other:?}"),
        }
    }

    /// `RsaSigner` must impl `Debug` without panicking — required by
    /// rustls's `Signer: Debug` bound. Trivial but the manual impl is
    /// hand-rolled (`Algorithm` doesn't derive Debug), so a smoke test
    /// guards against future fmt-impl regressions.
    #[test]
    fn rsa_signer_debug_smoke() {
        let der = gen_rsa_key_der();
        let key = RsaSigningKey::new(&der).expect("load");
        let signer = key.choose_scheme(RSA_SCHEMES).expect("scheme");
        let s = format!("{signer:?}");
        assert!(s.contains("RsaSigner"), "Debug output: {s}");
    }

    /// Contract: every scheme in `RSA_SCHEMES` must have a non-panicking
    /// mapping in `scheme_to_algorithm`. A regression that extends
    /// `RSA_SCHEMES` without extending the match arm would surface here
    /// rather than at signing time.
    #[test]
    fn scheme_to_algorithm_total_over_rsa_schemes() {
        for &scheme in RSA_SCHEMES {
            // Must not panic — `Algorithm` variants are private to
            // `security_framework`, so we only assert that the call
            // returns without unwinding.
            let _ = scheme_to_algorithm(scheme);
        }
    }

    #[test]
    fn choose_scheme_picks_pss512_when_offered_all() {
        let der = gen_rsa_key_der();
        let key = RsaSigningKey::new(&der).expect("load");
        let offered: Vec<SignatureScheme> = RSA_SCHEMES.iter().rev().copied().collect();
        let signer = key.choose_scheme(&offered).expect("scheme");
        assert_eq!(signer.scheme(), SignatureScheme::RSA_PSS_SHA512);
    }

    #[test]
    fn choose_scheme_returns_none_when_no_offered_overlap() {
        let der = gen_rsa_key_der();
        let key = RsaSigningKey::new(&der).expect("load");
        // Offer only ECDSA schemes; RSA key cannot satisfy them.
        let offered = [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
        ];
        assert!(key.choose_scheme(&offered).is_none());
    }

    /// End-to-end roundtrip per scheme: sign with our `Signer`, verify with
    /// our own `verify::SUPPORTED_SIG_ALGS` chain. This proves both halves
    /// agree on the wire format, which is the only thing rustls relies on.
    fn roundtrip(scheme: SignatureScheme) {
        let der = gen_rsa_key_der();
        let key = RsaSigningKey::new(&der).expect("load");
        let signer = key.choose_scheme(&[scheme]).expect("scheme");
        let msg = format!("rsa roundtrip {scheme:?}");
        let sig = signer.sign(msg.as_bytes()).expect("sign");

        // Verify via our public-side path.
        let pub_bytes = key
            .key
            .public_key()
            .expect("pub")
            .external_representation()
            .expect("ext")
            .bytes()
            .to_vec();
        let alg = crate::verify::SUPPORTED_SIG_ALGS
            .mapping
            .iter()
            .find(|(s, _)| *s == scheme)
            .and_then(|(_, algs)| algs.first())
            .expect("scheme in mapping");
        alg.verify_signature(&pub_bytes, msg.as_bytes(), &sig)
            .expect("verify");
    }

    #[test]
    fn roundtrip_rsa_pss_sha256() {
        roundtrip(SignatureScheme::RSA_PSS_SHA256);
    }
    #[test]
    fn roundtrip_rsa_pss_sha384() {
        roundtrip(SignatureScheme::RSA_PSS_SHA384);
    }
    #[test]
    fn roundtrip_rsa_pss_sha512() {
        roundtrip(SignatureScheme::RSA_PSS_SHA512);
    }
    #[test]
    fn roundtrip_rsa_pkcs1_sha256() {
        roundtrip(SignatureScheme::RSA_PKCS1_SHA256);
    }
    #[test]
    fn roundtrip_rsa_pkcs1_sha384() {
        roundtrip(SignatureScheme::RSA_PKCS1_SHA384);
    }
    #[test]
    fn roundtrip_rsa_pkcs1_sha512() {
        roundtrip(SignatureScheme::RSA_PKCS1_SHA512);
    }

    /// FIPS-4: RSA modulus < 2048 bits must be rejected at load time.
    /// Apple's `SecKeyCreateWithData` happily accepts 1024-bit RSA keys
    /// (Apple itself imposes no FIPS-mode restriction on the loader),
    /// so the check has to live in our code. Loading rcgen's smallest
    /// RSA key would be wasteful — generate a 1024-bit key directly via
    /// `SecKey::new` and re-encode its private bytes into a fake
    /// `PrivateKeyDer::Pkcs1` to drive the rejection path.
    #[test]
    fn rsa_1024_key_is_rejected() {
        use crate::ffi::security::seckey_block_size;
        use rustls::pki_types::PrivatePkcs1KeyDer;
        use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

        // Mint an Apple-side RSA-1024 key, extract its PKCS#1 private
        // bytes via Apple's external representation (`SecKeyCopy*` family
        // returns PKCS#1 for RSA), then feed those bytes back to
        // `RsaSigningKey::new` and expect the FIPS-4 gate to fire.
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::rsa());
        opts.set_size_in_bits(1024);
        let weak = SecKey::new(&opts).expect("apple 1024-bit RSA keygen");
        assert_eq!(
            seckey_block_size(&weak),
            128,
            "1024-bit modulus = 128 bytes"
        );
        let pkcs1_bytes = weak
            .external_representation()
            .expect("external_representation")
            .bytes()
            .to_vec();
        let der = PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(pkcs1_bytes));

        match RsaSigningKey::new(&der) {
            Err(Error::General(msg)) => assert!(
                msg.contains("below the FIPS 186-5 minimum of 2048") && msg.contains("1024-bit"),
                "FIPS-4 rejection must reference 2048-bit minimum and the actual key size, got {msg:?}"
            ),
            Err(other) => panic!("expected General error, got {other:?}"),
            Ok(_) => panic!("RSA-1024 was accepted; FIPS-4 gate is broken"),
        }
    }

    /// **TODO-4 / PSS salt-length regression-watch.** Apple's `SecKey.h`
    /// documents `kSecKeyAlgorithmRSASignatureMessagePSSSHA{256,384,512}`
    /// with `saltLength = 32/48/64` (= digest length), matching RFC 8446
    /// §4.2.3 and RFC 8017 §9.1. If Apple ever silently changes this in
    /// a future macOS SDK release, TLS 1.3 interop would break for any
    /// RFC-compliant peer and the FIPS-claim correctness would be lost.
    ///
    /// We catch the drift via **cross-implementation verification**: sign
    /// with Apple's path (our `RsaSigner`), then verify with the
    /// pure-Rust `rsa` crate using `Pss::new_with_salt::<D>(hash_len)` —
    /// which only accepts signatures whose salt is exactly `hash_len`
    /// bytes (the RFC-mandated value). A mismatch surfaces as a verify
    /// failure and fails this test.
    ///
    /// Coverage: all three SHA variants. Single test runs all three so a
    /// silent breakage of any one is caught.
    #[test]
    fn rsa_pss_apple_salt_length_matches_rfc8017() {
        use rsa::RsaPublicKey;
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pss::Pss;
        use sha2::{Digest, Sha256, Sha384, Sha512};

        let der = gen_rsa_key_der();
        let key = RsaSigningKey::new(&der).expect("load");

        // Apple's `external_representation` for RSA returns PKCS#1
        // RSAPublicKey DER (`SEQUENCE { modulus, publicExponent }`).
        let pub_bytes = key
            .key
            .public_key()
            .expect("pub")
            .external_representation()
            .expect("ext")
            .bytes()
            .to_vec();
        let pub_key = RsaPublicKey::from_pkcs1_der(&pub_bytes)
            .expect("parse Apple RSAPublicKey DER via rsa crate");

        // SHA-256 path: salt_len MUST be 32.
        {
            let signer = key
                .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .expect("scheme");
            let msg = b"pss-salt-256-regression";
            let sig = signer.sign(msg).expect("sign");
            let hashed: [u8; 32] = Sha256::digest(msg).into();
            pub_key
                .verify(Pss::new_with_salt::<Sha256>(32), &hashed, &sig)
                .expect(
                    "Apple PSS-SHA256 signature failed pure-Rust verify with \
                     salt_len=32 — Apple has silently changed its PSS salt-length \
                     default; TLS 1.3 interop and FIPS-claim correctness are broken",
                );
        }

        // SHA-384 path: salt_len MUST be 48.
        {
            let signer = key
                .choose_scheme(&[SignatureScheme::RSA_PSS_SHA384])
                .expect("scheme");
            let msg = b"pss-salt-384-regression";
            let sig = signer.sign(msg).expect("sign");
            let hashed = Sha384::digest(msg);
            pub_key
                .verify(Pss::new_with_salt::<Sha384>(48), &hashed, &sig)
                .expect(
                    "Apple PSS-SHA384 signature failed pure-Rust verify with \
                     salt_len=48 — see SHA-256 case for impact",
                );
        }

        // SHA-512 path: salt_len MUST be 64.
        {
            let signer = key
                .choose_scheme(&[SignatureScheme::RSA_PSS_SHA512])
                .expect("scheme");
            let msg = b"pss-salt-512-regression";
            let sig = signer.sign(msg).expect("sign");
            let hashed = Sha512::digest(msg);
            pub_key
                .verify(Pss::new_with_salt::<Sha512>(64), &hashed, &sig)
                .expect(
                    "Apple PSS-SHA512 signature failed pure-Rust verify with \
                     salt_len=64 — see SHA-256 case for impact",
                );
        }
    }

    /// **Test-gap #12.** RSA-4096 must be accepted (no upper modulus
    /// ceiling beyond what Apple itself enforces). Documents by positive
    /// example that the 2048-bit floor is a floor, not a single allowed
    /// size. Uses Apple's `SecKey::new` directly so we don't have to
    /// shell out to rcgen for a 4096-bit key (rcgen's RSA helper does
    /// not let us pick a size).
    #[test]
    fn rsa_4096_key_is_accepted_and_signs() {
        use crate::ffi::security::seckey_block_size;
        use rustls::pki_types::PrivatePkcs1KeyDer;
        use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::rsa());
        opts.set_size_in_bits(4096);
        let strong = SecKey::new(&opts).expect("apple 4096-bit RSA keygen");
        assert_eq!(
            seckey_block_size(&strong),
            512,
            "4096-bit modulus = 512 bytes"
        );

        let pkcs1_bytes = strong
            .external_representation()
            .expect("external_representation")
            .bytes()
            .to_vec();
        let der = PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(pkcs1_bytes));

        let key = RsaSigningKey::new(&der).expect("RSA-4096 must be accepted");
        let signer = key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .expect("scheme");
        let sig = signer.sign(b"4096-smoke").expect("sign with RSA-4096");
        // RSA-4096 signature is 512 bytes (modulus size).
        assert_eq!(sig.len(), 512, "RSA-4096 signature must be modulus-sized");
    }

    /// Concurrent signing with one `Arc<SigningKey>`: 16 threads × 64
    /// independent sign() calls each, all produce verify-able signatures.
    /// This is the contract rustls relies on -- `SigningKey` is wrapped in
    /// `Arc<dyn SigningKey>` and rustls hands clones to multiple handler
    /// threads. `RsaSigningKey` derives `Send + Sync` via auto-traits
    /// on `Arc<SecKey>` (SecKey itself carries upstream
    /// `unsafe impl Send + Sync` in security-framework); if either of
    /// those upstream contracts were unsound, a TSan/UBSan run would
    /// catch it here.
    #[test]
    fn concurrent_sign_with_shared_key() {
        use std::sync::Arc;
        use std::thread;

        let der = gen_rsa_key_der();
        // Keep a typed `Arc<RsaSigningKey>` for the test-side public-key
        // extraction; clone into `Arc<dyn SigningKey>` for the rustls
        // contract surface used by the threads. This avoids casting a
        // wide trait-object pointer to a thin concrete pointer, which
        // would rely on an unspecified Rust ABI invariant.
        let typed = Arc::new(RsaSigningKey::new(&der).expect("load"));
        let pub_bytes = typed
            .key
            .public_key()
            .expect("pub")
            .external_representation()
            .expect("ext")
            .bytes()
            .to_vec();
        let key: Arc<dyn SigningKey> = typed.clone();
        assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);

        let mut handles = vec![];
        for t in 0..16 {
            let key = Arc::clone(&key);
            let pub_bytes = pub_bytes.clone();
            handles.push(thread::spawn(move || {
                for i in 0..64 {
                    let signer = key
                        .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                        .expect("scheme");
                    let msg = format!("thread {t} iteration {i}");
                    let sig = signer.sign(msg.as_bytes()).expect("sign");
                    assert!(!sig.is_empty());
                    // Verify wire-correctness — sig must verify against
                    // our own verify path with the matching pub key.
                    let alg = crate::verify::SUPPORTED_SIG_ALGS
                        .mapping
                        .iter()
                        .find(|(s, _)| *s == SignatureScheme::RSA_PSS_SHA256)
                        .and_then(|(_, a)| a.first())
                        .expect("scheme");
                    alg.verify_signature(&pub_bytes, msg.as_bytes(), &sig)
                        .expect("concurrent verify");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread completed without panic");
        }
    }
}
