//! Final assembly of the [`rustls::crypto::CryptoProvider`].
//!
//! Combines:
//! - 2 TLS 1.3 cipher suites (AES-128/256-GCM with SHA-256/384)
//! - 4 TLS 1.2 GCM cipher suites (ECDHE_ECDSA / ECDHE_RSA × AES-128/256)
//! - 2 key exchange groups (P-256, P-384)
//! - 9 signature verification algorithms (ECDSA P-256/384/521 + RSA-PSS + RSA-PKCS#1)
//! - Apple `SecRandom` as `SecureRandom`
//! - `KeyProvider` for server-side TLS / mTLS (RSA + ECDSA P-256/384/521;
//!   see [`crate::signer`] and ADR 0004).
//!
//! All operations route through Apple corecrypto (FIPS-validated module).

use std::sync::{Arc, OnceLock};

use rustls::crypto::CipherSuiteCommon;
use rustls::crypto::CryptoProvider;
use rustls::crypto::KeyExchangeAlgorithm;
use rustls::{
    CipherSuite, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
};

use crate::hash::{SHA256, SHA384};
use crate::hkdf::{HKDF_SHA256, HKDF_SHA384};
use crate::kx::{SECP256R1, SECP384R1};
use crate::random::CoreCryptoRandom;
use crate::signer::{CoreCryptoKeyProvider, RSA_SCHEMES};
use crate::tls12;
use crate::tls13;
use crate::verify::SUPPORTED_SIG_ALGS;

// =========================================================================
// TLS 1.3 cipher suites
// =========================================================================

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            // RFC 8446 §5.5 / TLS WG guidance for AES-GCM: limit to 2^23.5
            // records before rekey. We use the conservative 2^23.
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &HKDF_SHA256,
        aead_alg: &tls13::AES_128_GCM,
        quic: None,
    });

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &HKDF_SHA384,
        aead_alg: &tls13::AES_256_GCM,
        quic: None,
    });

// =========================================================================
// TLS 1.2 cipher suites
// =========================================================================

pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SIG_SCHEMES,
        aead_alg: &tls12::AES_128_GCM,
        prf_provider: &tls12::PRF_SHA256,
    });

pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SIG_SCHEMES,
        aead_alg: &tls12::AES_256_GCM,
        prf_provider: &tls12::PRF_SHA384,
    });

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &tls12::AES_128_GCM,
        prf_provider: &tls12::PRF_SHA256,
    });

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &tls12::AES_256_GCM,
        prf_provider: &tls12::PRF_SHA384,
    });

const ECDSA_SIG_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
];

// RSA scheme list lives in `crate::signer::rsa::RSA_SCHEMES` so the signer
// and the TLS 1.2 cipher-suite definitions stay in sync (one source of
// truth — the constant is re-exported through `signer/mod.rs`).

// =========================================================================
// Default cipher-suite list
// =========================================================================

/// Full cipher-suite list including TLS 1.2 fallback. Only consumed by
/// [`default_provider`] when `feature = "fips"` is *not* active —
/// `fips_provider`-only builds skip this in favour of [`FIPS_CIPHER_SUITES`].
#[cfg(not(feature = "fips"))]
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS 1.3 preferred.
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    // TLS 1.2 fallback, ECDSA first then RSA, AES-256 first.
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

/// TLS 1.3-only cipher-suite list, used by [`fips_provider`].
///
/// TLS 1.2 cipher suites are excluded because the TLS 1.2 PRF on this
/// provider is a generic HMAC-P_hash composition without a dedicated
/// CAVS validation on macOS (Apple corecrypto exposes only HMAC + hash
/// primitives, not a separately validated TLS PRF). Including any TLS
/// 1.2 cipher suite would make `CryptoProvider::fips()` return `false`
/// (it is the AND of every cipher suite's `fips()`), which in turn
/// poisons `ClientConfig::fips()` / `ServerConfig::fips()`.
pub static FIPS_CIPHER_SUITES: &[SupportedCipherSuite] =
    &[TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];

// =========================================================================
// CryptoProvider construction
// =========================================================================

static SECURE_RANDOM: CoreCryptoRandom = CoreCryptoRandom;
static KEY_PROVIDER: CoreCryptoKeyProvider = CoreCryptoKeyProvider;

/// Process-wide cached `CryptoProvider` arcs. `CryptoProvider` contains
/// `Vec<SupportedCipherSuite>` and `Vec<&dyn SupportedKxGroup>` which
/// allocate on construction; rustls expects `Arc<CryptoProvider>`
/// downstream anyway, so caching here lets repeated `default_provider()`
/// / `fips_provider()` calls hand out cheap `Arc::clone`s instead of
/// re-allocating six `SupportedCipherSuite` slots every time.
///
/// The provider value itself is **immutable** (all components are
/// `&'static`), so a `OnceLock` is safe and race-free across threads.
#[cfg(not(feature = "fips"))]
static DEFAULT_PROVIDER_CACHE: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
static FIPS_PROVIDER_CACHE: OnceLock<Arc<CryptoProvider>> = OnceLock::new();

#[cfg(not(feature = "fips"))]
fn build_default() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: vec![&SECP256R1, &SECP384R1],
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SECURE_RANDOM,
        key_provider: &KEY_PROVIDER,
    }
}

fn build_fips() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: FIPS_CIPHER_SUITES.to_vec(),
        kx_groups: vec![&SECP256R1, &SECP384R1],
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SECURE_RANDOM,
        key_provider: &KEY_PROVIDER,
    }
}

/// Construct the corecrypto-backed [`CryptoProvider`].
///
/// **Without `feature = "fips"`** (default): TLS 1.2 + TLS 1.3 cipher
/// suites, `CryptoProvider::fips() == false` (because TLS 1.2 PRF is not
/// CAVS-validated on macOS — see [`fips_provider`] / ADR 0004). Use for
/// general-purpose outbound TLS where TLS 1.2 fallback is needed for
/// interop with older endpoints.
///
/// **With `feature = "fips"`**: this function returns the same value as
/// [`fips_provider`] — TLS 1.3 only, `CryptoProvider::fips() == true`.
/// Mirrors the feature-flag pattern in `rustls-cng-crypto`: downstream
/// callers compiled with `--features fips` get the FIPS-claim provider
/// automatically without having to switch factory calls.
///
/// All cryptographic operations route through Apple corecrypto in both
/// modes. Returns a fresh `CryptoProvider` value (rustls's contract);
/// internally a cached process-wide `Arc<CryptoProvider>` is cloned, so
/// this is allocation-free after the first call. Callers that want the
/// cached `Arc` directly can use [`default_provider_arc`].
pub fn default_provider() -> CryptoProvider {
    (*default_provider_arc()).clone()
}

/// Same as [`default_provider`] but returns the process-wide cached
/// `Arc<CryptoProvider>` directly, avoiding even the per-call
/// `CryptoProvider::clone`.
pub fn default_provider_arc() -> Arc<CryptoProvider> {
    // Under `feature = "fips"`, `default_provider*` is aliased to
    // `fips_provider*` — same cached Arc, same TLS-1.3-only set.
    #[cfg(feature = "fips")]
    {
        fips_provider_arc()
    }
    #[cfg(not(feature = "fips"))]
    {
        Arc::clone(DEFAULT_PROVIDER_CACHE.get_or_init(|| {
            // Prime the OE witness so its one-time `tracing::warn!` fires
            // here even if the caller never asks for the FIPS factory.
            // Per ADR 0004 + the FIPS-witness rework: no panic.
            let _ = crate::oe::fips_witness_ok();
            Arc::new(build_default())
        }))
    }
}

/// Construct the corecrypto-backed [`CryptoProvider`] restricted to
/// TLS 1.3 cipher suites only.
///
/// `CryptoProvider::fips()` returns `true` for this provider — every
/// cipher suite, key-exchange group, signature-verification algorithm,
/// RNG and key-provider component routes through a FIPS-validated
/// primitive. Downstream `ClientConfig::fips()` / `ServerConfig::fips()`
/// is `true` when the negotiated protocol is TLS 1.3, which is
/// guaranteed when constructed via
/// `builder_with_provider(fips_provider()).with_protocol_versions(...)`
/// restricting to TLS 1.3 (and, for TLS 1.2 fallback eventually, setting
/// `require_ems = true`).
///
/// **The FIPS claim still depends on the running macOS version being
/// covered by the current Apple corecrypto CMVP certificate** — see the
/// crate README's "Open questions / TODO" section and the per-OS-version
/// CMVP search referenced there.
pub fn fips_provider() -> CryptoProvider {
    (*fips_provider_arc()).clone()
}

/// Same as [`fips_provider`] but returns the process-wide cached
/// `Arc<CryptoProvider>` directly.
///
/// **Side effect on first call**: primes [`crate::oe::fips_witness_ok`]
/// so the one-time `tracing::warn!` is emitted on OE-validation
/// failure. The provider itself is still constructed and usable; the
/// runtime FIPS witness simply reports `false` everywhere on a host
/// whose macOS major is outside [`crate::oe::SUPPORTED_OE_MACOS_MAJOR`].
///
/// This crate **does not panic** on OE failure (per the C-2 rework).
/// The downstream signal is `CryptoProvider::fips() == false`, mirroring
/// `rustls-cng-crypto`'s posture on Windows when the OS FIPS-mode flag
/// is not set. The [`crate::oe::OE_OVERRIDE_ENV`] env-var forces the
/// witness back to `true` for CI on pre-release macOS — never for
/// production.
pub fn fips_provider_arc() -> Arc<CryptoProvider> {
    Arc::clone(FIPS_PROVIDER_CACHE.get_or_init(|| {
        // Prime the witness on first construction so OE telemetry surfaces
        // exactly once. The return value is consulted later by every
        // `fips()` impl across the crate.
        let _ = crate::oe::fips_witness_ok();
        Arc::new(build_fips())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    /// The provider's `secure_random` must produce distinct output across
    /// calls. A broken delegation (e.g. returning a constant) would fail.
    #[test]
    fn secure_random_produces_distinct_output_across_calls() {
        let p = default_provider();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        p.secure_random.fill(&mut a).expect("fill a");
        p.secure_random.fill(&mut b).expect("fill b");
        assert_ne!(a, b);
    }

    /// The provider's `key_provider` rejects obviously-malformed input
    /// with the documented marker error rather than a generic failure or
    /// panic. Tightened from a plain `.is_err()` so a regression that
    /// returns `Err(Error::Other(...))` (or worse, that silently accepts
    /// the bytes and surfaces a panic during `sign()` later) is caught
    /// here at load time.
    #[test]
    fn key_provider_rejects_garbage_private_key() {
        let p = default_provider();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0u8; 16]));
        match p.key_provider.load_private_key(key) {
            Err(rustls::Error::General(msg)) => assert!(
                msg.contains("unsupported private-key type"),
                "garbage rejection must use the documented marker, got {msg:?}"
            ),
            other => panic!("expected Error::General, got {other:?}"),
        }
    }

    /// Without `feature = "fips"`: 2 TLS 1.3 + 4 TLS 1.2 cipher suites
    /// are exposed — without all of them, rustls would fail to negotiate
    /// with peers that only offer a subset.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn provider_exposes_six_cipher_suites() {
        let p = default_provider();
        assert_eq!(p.cipher_suites.len(), 6);
    }

    /// With `feature = "fips"`: `default_provider()` is aliased to
    /// `fips_provider()`, so only the 2 TLS 1.3 suites are exposed.
    #[cfg(feature = "fips")]
    #[test]
    fn provider_under_fips_exposes_two_tls13_suites_only() {
        let p = default_provider();
        assert_eq!(p.cipher_suites.len(), 2);
        for cs in &p.cipher_suites {
            assert!(
                matches!(cs, rustls::SupportedCipherSuite::Tls13(_)),
                "fips-feature provider must contain only TLS 1.3 suites"
            );
        }
        assert!(
            p.fips(),
            "default_provider().fips() under feature=fips must be true"
        );
    }

    /// Both NIST P-curves are exposed.
    #[test]
    fn provider_exposes_two_kx_groups() {
        let p = default_provider();
        assert_eq!(p.kx_groups.len(), 2);
        // ECDHE relies on at least P-256 being available; assert both are.
        let names: Vec<_> = p.kx_groups.iter().map(|g| g.name()).collect();
        assert!(names.contains(&rustls::NamedGroup::secp256r1));
        assert!(names.contains(&rustls::NamedGroup::secp384r1));
    }

    /// Without `feature = "fips"`: `default_provider()` includes TLS 1.2
    /// cipher suites, whose PRF is not CAVS-validated on macOS. Per
    /// rustls's `CryptoProvider::fips()` (AND over every cipher suite +
    /// every kx group + sig-verify + RNG + key-provider), this means
    /// `default_provider().fips() == false`.
    ///
    /// This is the honest stance — claim FIPS only via `fips_provider()`,
    /// or compile with `--features fips` to flip `default_provider()`
    /// itself to the FIPS path.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn default_provider_is_not_fips_due_to_tls12_prf() {
        let p = default_provider();
        // Component check first — narrows the blame on regression.
        for cs in &p.cipher_suites {
            let suite = cs.suite();
            let is_tls13 = matches!(cs, rustls::SupportedCipherSuite::Tls13(_));
            if is_tls13 {
                assert!(cs.fips(), "TLS 1.3 suite {suite:?} must claim FIPS");
            } else {
                assert!(
                    !cs.fips(),
                    "TLS 1.2 suite {suite:?} must NOT claim FIPS (PRF not CAVS-validated)"
                );
            }
        }
        for kx in &p.kx_groups {
            assert!(kx.fips(), "kx group {:?} not FIPS", kx.name());
        }
        assert!(p.signature_verification_algorithms.fips());
        assert!(p.secure_random.fips());
        assert!(p.key_provider.fips());
        // Overall: false, because at least one TLS 1.2 cipher suite is in
        // the set.
        assert!(
            !p.fips(),
            "default_provider() must not claim FIPS while TLS 1.2 suites are present"
        );
    }

    /// `fips_provider()` restricts to TLS 1.3 cipher suites only — every
    /// component is FIPS, so `CryptoProvider::fips() == true`.
    #[test]
    fn fips_provider_claims_fips() {
        let p = fips_provider();
        assert_eq!(
            p.cipher_suites.len(),
            2,
            "fips_provider must expose exactly the two TLS 1.3 GCM suites"
        );
        for cs in &p.cipher_suites {
            assert!(
                matches!(cs, rustls::SupportedCipherSuite::Tls13(_)),
                "fips_provider must contain only TLS 1.3 suites"
            );
            assert!(cs.fips(), "TLS 1.3 suite must claim FIPS");
        }
        assert!(p.fips(), "fips_provider().fips() must be true");
    }

    /// A `ClientConfig` built on `fips_provider()` + EMS-required must
    /// advertise FIPS. Catches regressions where any component flips
    /// `fips()` to false.
    #[test]
    fn client_config_on_fips_provider_with_ems_advertises_fips() {
        let mut config = rustls::ClientConfig::builder_with_provider(fips_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("protocol versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.require_ems = true;

        assert!(
            config.fips(),
            "ClientConfig on fips_provider() with require_ems=true must claim FIPS"
        );
    }

    /// **A-2 regression.** Every cipher suite in our static list must
    /// carry the documented AES-GCM `confidentiality_limit` of `1 << 23`
    /// records. rustls's `CipherSuiteCommon` doc (rustls 0.23) cites
    /// `2^24` as the AES-GCM bound to keep attack probability ≤ 2^-60
    /// (see AEBounds / draft-irtf-cfrg-aead-limits-08); we run at the
    /// slightly more conservative `2^23` per CipherSuiteCommon-construction
    /// in `provider.rs`. This test locks the constant so an accidental
    /// future drift (e.g. `1 << 27` for a perf claim) is caught here
    /// rather than going unnoticed into production.
    ///
    /// rustls's TLS-side `CipherSuiteCommon` has no `integrity_limit`
    /// field — that exists on the QUIC path only — so we cannot pin one
    /// here; the spirit of the A-2 review item (lock AEAD bounds) is
    /// addressed by the confidentiality side.
    #[test]
    fn cipher_suites_use_documented_aes_gcm_confidentiality_limit() {
        const EXPECTED: u64 = 1 << 23;
        let suites: &[SupportedCipherSuite] = &[
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        for cs in suites {
            let limit = match cs {
                SupportedCipherSuite::Tls13(s) => s.common.confidentiality_limit,
                SupportedCipherSuite::Tls12(s) => s.common.confidentiality_limit,
            };
            assert_eq!(
                limit,
                EXPECTED,
                "cipher suite {:?} drifted from documented AES-GCM confidentiality_limit",
                cs.suite()
            );
        }
    }

    /// And the contrapositive (only without `feature = "fips"`): a
    /// `ClientConfig` on `default_provider()` must NOT claim FIPS, no
    /// matter the protocol-version restriction. rustls evaluates
    /// `provider.fips()` once at config build time, so having TLS 1.2
    /// suites in the provider poisons the claim even with
    /// `with_protocol_versions(&[TLS13])`.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn client_config_on_default_provider_does_not_claim_fips() {
        let mut config = rustls::ClientConfig::builder_with_provider(default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("protocol versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.require_ems = true;

        assert!(
            !config.fips(),
            "default_provider's TLS 1.2 suites must keep ClientConfig::fips() false"
        );
    }
}
