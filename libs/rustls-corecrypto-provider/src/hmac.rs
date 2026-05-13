//! HMAC-SHA-256 / HMAC-SHA-384 implementations of [`rustls::crypto::hmac::Hmac`].
//!
//! Backed by CommonCrypto's `CCHmac*` family. We keep a `CCHmacContext`
//! initialised with the key once at `with_key`-time; on each `sign` we
//! memcpy-clone it (the struct is POD with the key state baked in), then
//! Update + Final on the clone.

use core::ffi::c_void;
use core::mem::MaybeUninit;

use rustls::crypto::hmac::{Hmac, Key, Tag};
use zeroize::Zeroize;

use crate::ffi::commoncrypto as cc;

/// Maximum digest size across every HMAC algorithm this module wires up.
/// Sized to SHA-512 (64 bytes) so a future contributor adding
/// `kCCHmacAlgSHA512` to [`HmacSha256::with_key`] / [`HmacSha384::with_key`]
/// cannot silently overflow the per-sign stack buffer.
///
/// **Invariant** (pinned by the `const _: () = assert!(...)` below): the
/// constant must be greater than or equal to every `tag_len` reachable
/// from [`HmacKey::new`]'s call sites.
const MAX_HMAC_DIGEST: usize = 64;

// SHA-256 = 32 bytes, SHA-384 = 48 bytes; both must fit. Compile-time
// guard so an accidental shrink of MAX_HMAC_DIGEST fails the build, not
// the runtime. Test-gap #7.
const _: () = assert!(MAX_HMAC_DIGEST >= 32);
const _: () = assert!(MAX_HMAC_DIGEST >= 48);
const _: () = assert!(MAX_HMAC_DIGEST >= 64); // anticipates SHA-512 addition.

// =========================================================================
// HMAC-SHA-256
// =========================================================================

#[derive(Debug)]
pub struct HmacSha256;

pub static HMAC_SHA256: HmacSha256 = HmacSha256;

impl Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacKey::new(cc::kCCHmacAlgSHA256, key, 32))
    }

    fn hash_output_len(&self) -> usize {
        32
    }

    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

// =========================================================================
// HMAC-SHA-384
// =========================================================================

#[derive(Debug)]
pub struct HmacSha384;

pub static HMAC_SHA384: HmacSha384 = HmacSha384;

impl Hmac for HmacSha384 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacKey::new(cc::kCCHmacAlgSHA384, key, 48))
    }

    fn hash_output_len(&self) -> usize {
        48
    }

    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

// =========================================================================
// shared key wrapper
// =========================================================================

/// A keyed HMAC context.
///
/// The C-side `CCHmacContext` is a fixed-size POD; we memcpy-clone it per
/// `sign` to support multiple signing operations with the same key.
///
/// `Send + Sync` are inferred from the fields — `CCHmacAlgorithm` is a
/// `u32`, `CCHmacContext` is `[u32; 96]`, `tag_len` is a `usize`; all
/// auto-implement `Send + Sync`. `sign_concat` takes `&self` and clones
/// `self.template` byte-for-byte into a local, so concurrent calls
/// cannot race on the C-side state; CommonCrypto's HMAC primitives do
/// not touch process-wide state.
struct HmacKey {
    algorithm: cc::CCHmacAlgorithm,
    template: cc::CCHmacContext,
    tag_len: usize,
}

impl HmacKey {
    fn new(algorithm: cc::CCHmacAlgorithm, key: &[u8], tag_len: usize) -> Self {
        let mut template = MaybeUninit::<cc::CCHmacContext>::uninit();
        // SAFETY: `CCHmacInit` initialises every field of the context. Passing
        // empty key (`key.len() == 0`) is documented to derive a zero-length
        // key, which is sound; rustls never invokes that path in practice.
        unsafe {
            cc::CCHmacInit(
                template.as_mut_ptr(),
                algorithm,
                key.as_ptr() as *const c_void,
                key.len(),
            );
            Self {
                algorithm,
                template: template.assume_init(),
                tag_len,
            }
        }
    }
}

impl Drop for HmacKey {
    fn drop(&mut self) {
        // CCHmacContext's `ctx: [u32; 96]` field is exposed; zero it before
        // release. Defense-in-depth — Apple may also zeroize internally but
        // we don't rely on that.
        self.template.ctx.zeroize();
    }
}

impl Key for HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        // memcpy-clone the keyed template so we can call Update+Final without
        // disturbing it (the trait permits repeated signing with one Key).
        let mut ctx = self.template.clone();

        let _ = self.algorithm; // silence unused-field lint; kept for diagnostics
        // Sized to `MAX_HMAC_DIGEST` (SHA-512 width) so a future
        // SHA-512 contributor cannot silently overflow this buffer.
        // The compile-time `const _: () = assert!(MAX_HMAC_DIGEST >= 48)`
        // above guarantees this is wide enough for every algorithm
        // currently registered.
        let mut out = [0u8; MAX_HMAC_DIGEST];
        // `assert!` (not `debug_assert!`) — the cost is one cmp/jmp per
        // HMAC, and the buffer-overflow class is gone for good even if a
        // future caller passes a > 64-byte digest. The compile-time
        // `const _: () = assert!(MAX_HMAC_DIGEST >= …)` guards above make
        // this unreachable for the registered algorithms today, but
        // belt-and-braces is cheap.
        assert!(
            self.tag_len <= MAX_HMAC_DIGEST,
            "HMAC tag_len {} exceeds MAX_HMAC_DIGEST {MAX_HMAC_DIGEST}",
            self.tag_len
        );

        // SAFETY: ctx is fully initialised; all data pointers are valid for
        // the given lengths; out is sized to fit the largest tag.
        unsafe {
            if !first.is_empty() {
                cc::CCHmacUpdate(&mut ctx, first.as_ptr() as *const c_void, first.len());
            }
            for chunk in middle {
                if chunk.is_empty() {
                    continue;
                }
                cc::CCHmacUpdate(&mut ctx, chunk.as_ptr() as *const c_void, chunk.len());
            }
            if !last.is_empty() {
                cc::CCHmacUpdate(&mut ctx, last.as_ptr() as *const c_void, last.len());
            }
            cc::CCHmacFinal(&mut ctx, out.as_mut_ptr() as *mut c_void);
        }

        // Zero the cloned context after use.
        ctx.ctx.zeroize();

        let tag = Tag::new(&out[..self.tag_len]);
        // Wipe our local MAC buffer — the constructed `Tag` owns its own copy.
        out.zeroize();
        tag
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 1 — HMAC-SHA-256 with 20×0x0b key, "Hi There".
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let tag = HMAC_SHA256.with_key(&key).sign(&[data]);
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        assert_eq!(tag.as_ref(), expected.as_slice());
    }

    /// RFC 4231 test case 2 — "Jefe" key, "what do ya want for nothing?".
    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let tag = HMAC_SHA256.with_key(key).sign(&[data]);
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        assert_eq!(tag.as_ref(), expected.as_slice());
    }

    /// RFC 4231 test case 1 — HMAC-SHA-384, 20×0x0b key, "Hi There".
    #[test]
    fn hmac_sha384_rfc4231_case1() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let tag = HMAC_SHA384.with_key(&key).sign(&[data]);
        let expected = hex::decode(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        )
        .unwrap();
        assert_eq!(tag.as_ref(), expected.as_slice());
    }

    /// Multi-chunk update should match single-shot.
    #[test]
    fn hmac_sha256_multichunk_matches_oneshot() {
        let key = vec![0x42u8; 32];
        let single = HMAC_SHA256.with_key(&key).sign(&[b"hello world"]);
        let chunked = HMAC_SHA256.with_key(&key).sign(&[b"hel", b"lo ", b"world"]);
        assert_eq!(single.as_ref(), chunked.as_ref());
    }

    /// `sign_concat(first, middle, last)` should match `sign([first || middle || last])`.
    #[test]
    fn hmac_sha256_sign_concat() {
        let key = vec![0x42u8; 32];
        let direct = HMAC_SHA256.with_key(&key).sign(&[b"prefix-body-suffix"]);
        let concat = HMAC_SHA256
            .with_key(&key)
            .sign_concat(b"prefix-", &[b"body"], b"-suffix");
        assert_eq!(direct.as_ref(), concat.as_ref());
    }

    /// `hash_output_len()` and `tag_len()` are part of rustls's `Hmac` /
    /// `Key` trait contract. Validate against actual tag length.
    #[test]
    fn hmac_sha256_contract_accessors_match_actual_tag() {
        let key = HMAC_SHA256.with_key(b"k");
        let tag = key.sign(&[b"data"]);
        assert_eq!(tag.as_ref().len(), key.tag_len());
        assert_eq!(key.tag_len(), 32);
        assert_eq!(HMAC_SHA256.hash_output_len(), 32);
    }

    #[test]
    fn hmac_sha384_contract_accessors_match_actual_tag() {
        let key = HMAC_SHA384.with_key(b"k");
        let tag = key.sign(&[b"data"]);
        assert_eq!(tag.as_ref().len(), key.tag_len());
        assert_eq!(key.tag_len(), 48);
        assert_eq!(HMAC_SHA384.hash_output_len(), 48);
    }

    /// Different keys must produce different MACs over the same message.
    /// A bug that ignored the key would silently pass other vector tests.
    #[test]
    fn hmac_sha256_different_keys_diverge() {
        let a = HMAC_SHA256.with_key(b"key-a").sign(&[b"message"]);
        let b = HMAC_SHA256.with_key(b"key-b").sign(&[b"message"]);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    /// HMAC of empty data must not panic and must be deterministic.
    /// Verified against the value produced by the same key on a different
    /// invocation — catches accidental nondeterminism (e.g. uninit memory).
    #[test]
    fn hmac_sha256_empty_data_is_deterministic() {
        let key = HMAC_SHA256.with_key(b"some-key");
        let a = key.sign(&[]);
        let b = key.sign(&[b""]);
        assert_eq!(a.as_ref(), b.as_ref());
        assert_eq!(a.as_ref().len(), 32);
    }

    /// FIPS-claim contract.
    #[test]
    fn hmac_advertises_fips() {
        assert!(HMAC_SHA256.fips());
        assert!(HMAC_SHA384.fips());
    }

    /// Reusing the same `Key` for two signs must produce identical results.
    #[test]
    fn hmac_sha256_reuse_key() {
        let key = vec![0x42u8; 32];
        let mac = HMAC_SHA256.with_key(&key);
        let a = mac.sign(&[b"data"]);
        let b = mac.sign(&[b"data"]);
        assert_eq!(a.as_ref(), b.as_ref());
    }

    /// **Test-gap #1.** Concurrent signing with one `Arc<dyn Key>`: 16
    /// threads × 64 independent `sign()` calls each, all producing the
    /// same tag as a single-thread reference (since the message bytes
    /// and key are identical). Pins the auto-`Send + Sync` shape of
    /// `HmacKey` — `sign_concat` takes `&self` and clones
    /// `self.template` into a local before any C-side mutation, so
    /// concurrent readers of `self.template` must be sound.
    #[test]
    fn hmac_concurrent_sign_with_shared_key() {
        use std::sync::Arc;
        use std::thread;

        let key_bytes = vec![0x77u8; 32];
        let key: Arc<dyn Key> = HMAC_SHA256.with_key(&key_bytes).into();

        let msg: &[u8] = b"concurrent-hmac-message";
        let reference = HMAC_SHA256.with_key(&key_bytes).sign(&[msg]);
        let reference_bytes = reference.as_ref().to_vec();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let key = Arc::clone(&key);
            let expected = reference_bytes.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..64 {
                    let tag = key.sign(&[msg]);
                    assert_eq!(tag.as_ref(), expected.as_slice());
                }
            }));
        }
        for h in handles {
            h.join().expect("hmac thread did not panic");
        }
    }
}
