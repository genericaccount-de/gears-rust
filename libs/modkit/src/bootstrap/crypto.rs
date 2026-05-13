use std::sync::OnceLock;

/// Error returned when the crypto provider cannot be installed.
// `Clone` required by `OnceLock<Result<_>>` cache in `init_crypto_provider` --
// the cached result is cloned on every call.
// `PartialEq`/`Eq` used by tests asserting the cached result is stable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoProviderError {
    /// Another crypto provider was already installed (FIPS mode).
    #[error("failed to install FIPS crypto provider - another provider is already installed")]
    FipsProviderConflict,
}

static INIT_RESULT: OnceLock<Result<(), CryptoProviderError>> = OnceLock::new();

/// Install the process-wide default rustls [`CryptoProvider`](rustls::crypto::CryptoProvider).
///
/// Dispatch:
///
/// - **`fips` feature + macOS**: installs the Apple corecrypto-backed provider
///   from `rustls-corecrypto-provider`, **restricted to TLS 1.3 cipher
///   suites** via `fips_provider()`. corecrypto is shipped inside macOS and
///   validated by Apple under FIPS 140-3 per OS release; see
///   <https://csrc.nist.gov/projects/cryptographic-module-validation-program>
///   for the cert matching the running macOS version. TLS 1.2 cipher suites
///   are excluded under `fips` because Apple does not expose a separately
///   CAVS-validated TLS PRF primitive (unlike aws-lc-fips on Linux); see
///   the `cyberware-rustls-corecrypto-provider` README "FIPS claim boundaries"
///   section. On macOS the `rustls/fips` feature is not activated (see
///   `rustls-fips-shim`), so the AWS-LC FIPS dylib is not linked.
/// - **`fips` feature + non-macOS** (Linux, etc.): installs the FIPS-validated
///   AWS-LC provider (`aws-lc-fips-sys`, NIST Certificate #4816). The cert's OE
///   covers Linux but not Darwin, which is why the macOS branch uses a
///   different provider.
/// - **Standard mode** (no `fips` feature): installs the `aws-lc-rs` provider
///   explicitly. This is required because both `ring` and `aws-lc-rs` are
///   compiled into the binary (ring via `aliri`/`pingora-rustls`), and rustls
///   0.23 panics when it cannot auto-detect a single provider. Conflicts here
///   are non-fatal: if another provider was installed first, it stays active,
///   the conflict is logged at `warn!`, and `Ok(())` is returned.
///
/// This **must** be called before any TLS configuration, HTTP client, database
/// connection, or JWT operation is created.
///
/// Safe to call multiple times -- only the first invocation has an effect;
/// subsequent calls return the cached first-call result.
///
/// # FIPS-claim caveats
///
/// On the resulting provider, `provider.fips() == true` is a **runtime
/// witness** under the witness-pattern rework — it is `true` only when both
/// (a) every primitive routes through a CMVP-validated module *and* (b)
/// the runtime OE check agrees. It is no longer an unconditional design-
/// intent claim.
///
/// **macOS**: the corecrypto crate runs an OE check at first provider
/// construction (`cyberware_rustls_corecrypto_provider::oe::fips_witness_ok`).
/// On a macOS major outside the active corecrypto CMVP cert OE, **every**
/// `fips()` impl in the provider returns `false` and a single
/// `tracing::warn!` is emitted. There is **no panic** — downstream code
/// that depends on `ClientConfig::fips()` / `ServerConfig::fips()` must
/// handle the `false` case explicitly (see
/// `modkit_http::tls::apply_fips_hardening` for the canonical pattern,
/// which returns `Err` instead of asserting). The
/// `CYBERWARE_FIPS_OE_OVERRIDE=1` env-var forces the witness to `true`
/// for CI on pre-release macOS — never for production. See the
/// `cyberware-rustls-corecrypto-provider` README "Runtime FIPS witness" section
/// and FIPS PRD §8.3.
///
/// **Linux / Windows**: runtime OE-validation is not yet implemented; OE
/// coverage is verified via the release checklist (manual CMVP cert search,
/// PRD §9.3). Tracked as a follow-up in PRD §10.
///
/// # Errors
///
/// Returns [`CryptoProviderError::FipsProviderConflict`] if the `fips` feature
/// is enabled and another rustls provider was installed first.
pub fn init_crypto_provider() -> Result<(), CryptoProviderError> {
    INIT_RESULT
        .get_or_init(|| {
            #[cfg(all(feature = "fips", target_os = "macos"))]
            {
                // Under modkit's `fips` feature the dependency tree
                // activates `rustls-corecrypto-provider/fips`, which
                // routes `default_provider()` to the TLS-1.3-only FIPS-
                // claim variant — same pattern as `rustls-cng-crypto`'s
                // feature flag. We therefore install the unified entry
                // point (no need to remember which factory under which
                // build profile).
                if let Err(prev) = rustls_corecrypto_provider::default_provider().install_default()
                {
                    tracing::error!(
                        previous_provider = ?prev,
                        "FIPS crypto provider conflict: another rustls provider was already installed"
                    );
                    return Err(CryptoProviderError::FipsProviderConflict);
                }
                tracing::info!("FIPS-140-3 crypto provider installed (Apple corecrypto, macOS, TLS 1.3-only)");
            }

            #[cfg(all(feature = "fips", not(target_os = "macos")))]
            {
                if let Err(prev) = rustls::crypto::default_fips_provider().install_default() {
                    tracing::error!(
                        previous_provider = ?prev,
                        "FIPS crypto provider conflict: another rustls provider was already installed"
                    );
                    return Err(CryptoProviderError::FipsProviderConflict);
                }
                tracing::info!("FIPS-140-3 crypto provider installed (AWS-LC FIPS module)");
            }

            #[cfg(not(feature = "fips"))]
            {
                if let Err(prev) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
                    // Non-fatal: another provider is already active, TLS still works.
                    tracing::warn!(
                        previous_provider = ?prev,
                        "aws-lc-rs crypto provider not installed: another default provider was already set"
                    );
                } else {
                    tracing::info!("aws-lc-rs crypto provider installed");
                }
            }

            Ok(())
        })
        .clone()
}
