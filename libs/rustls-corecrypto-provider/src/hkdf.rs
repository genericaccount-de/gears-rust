//! HKDF (RFC 5869) implementation of [`rustls::crypto::tls13::Hkdf`].
//!
//! Pure Rust on top of our HMAC primitives — RFC 5869 specifies HKDF entirely
//! in terms of HMAC, so no additional FFI is needed. The PRK and intermediate
//! `T(i)` values are stored on the stack, zeroized on drop.

use rustls::crypto::hmac::Hmac;
use rustls::crypto::hmac::Tag;
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use zeroize::{Zeroize, Zeroizing};

use crate::hmac::{HMAC_SHA256, HMAC_SHA384};

// =========================================================================
// HKDF-SHA-256
// =========================================================================

#[derive(Debug)]
pub struct HkdfSha256;

pub static HKDF_SHA256: HkdfSha256 = HkdfSha256;

impl Hkdf for HkdfSha256 {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        extract::<32>(&HMAC_SHA256, salt, &[0u8; 32])
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        extract::<32>(&HMAC_SHA256, salt, secret)
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(Sha256Expander {
            prk: copy_prk::<32>(okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        HMAC_SHA256.with_key(key.as_ref()).sign(&[message])
    }

    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

// =========================================================================
// HKDF-SHA-384
// =========================================================================

#[derive(Debug)]
pub struct HkdfSha384;

pub static HKDF_SHA384: HkdfSha384 = HkdfSha384;

impl Hkdf for HkdfSha384 {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        extract::<48>(&HMAC_SHA384, salt, &[0u8; 48])
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        extract::<48>(&HMAC_SHA384, salt, secret)
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(Sha384Expander {
            prk: copy_prk::<48>(okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        HMAC_SHA384.with_key(key.as_ref()).sign(&[message])
    }

    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

// =========================================================================
// extract / expand machinery
// =========================================================================

fn extract<const N: usize>(
    hmac: &dyn Hmac,
    salt: Option<&[u8]>,
    secret: &[u8],
) -> Box<dyn HkdfExpander>
where
    Sha256Or384Expander<N>: HkdfExpander + 'static,
{
    let salt_bytes;
    let salt_ref: &[u8] = match salt {
        Some(s) => s,
        None => {
            salt_bytes = [0u8; N];
            &salt_bytes
        }
    };
    let tag = hmac.with_key(salt_ref).sign(&[secret]);
    let mut prk = [0u8; N];
    prk.copy_from_slice(tag.as_ref());
    Box::new(Sha256Or384Expander::<N> { prk })
}

fn copy_prk<const N: usize>(bytes: &[u8]) -> [u8; N] {
    assert_eq!(
        bytes.len(),
        N,
        "OkmBlock length must match HKDF hash output length"
    );
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

/// Generic expander parameterised by hash output length.
///
/// We implement the trait twice (via type aliases) for the SHA-256 (N=32)
/// and SHA-384 (N=48) widths, because the `HkdfExpander` impl needs to know
/// which HMAC primitive to call.
struct Sha256Or384Expander<const N: usize> {
    prk: [u8; N],
}

impl<const N: usize> Drop for Sha256Or384Expander<N> {
    fn drop(&mut self) {
        self.prk.zeroize();
    }
}

type Sha256Expander = Sha256Or384Expander<32>;
type Sha384Expander = Sha256Or384Expander<48>;

fn expand<const N: usize>(
    hmac: &dyn Hmac,
    prk: &[u8; N],
    info: &[&[u8]],
    output: &mut [u8],
) -> Result<(), OutputLengthError> {
    // RFC 5869 §2.3: L ≤ 255 · HashLen.
    if output.len() > 255 * N {
        return Err(OutputLengthError);
    }
    let key = hmac.with_key(prk);
    // `prev` carries T(i-1), which is HKDF intermediate output and so
    // sensitive. Wrapped in `Zeroizing` so an unwind from inside the
    // loop (e.g. a panicking custom HMAC impl) still wipes it. Sized to
    // SHA-384 (48 bytes) — the upper bound of our registered hashes.
    let mut prev: Zeroizing<[u8; 48]> = Zeroizing::new([0u8; 48]);
    let mut prev_len = 0usize;
    let mut written = 0usize;
    let mut counter: u8 = 1;

    while written < output.len() {
        // T(i) = HMAC(PRK, T(i-1) || info... || i)
        let counter_byte = [counter];
        // We must build the input slice list dynamically; rustls hmac's
        // `sign(slices)` walks them in order.
        let mut chunks: Vec<&[u8]> = Vec::with_capacity(info.len() + 2);
        if prev_len > 0 {
            chunks.push(&prev[..prev_len]);
        }
        for c in info {
            chunks.push(*c);
        }
        chunks.push(&counter_byte);

        let tag = key.sign(&chunks);
        let block = tag.as_ref();
        debug_assert_eq!(block.len(), N);

        let take = core::cmp::min(N, output.len() - written);
        output[written..written + take].copy_from_slice(&block[..take]);
        written += take;

        // Carry T(i) forward.
        prev[..N].copy_from_slice(block);
        prev_len = N;
        counter = counter.wrapping_add(1);
        if counter == 0 {
            // Should have already returned via length check above.
            return Err(OutputLengthError);
        }
    }

    // `prev`'s Drop wipes the residual T(i) — explicit zeroize would be
    // redundant.
    Ok(())
}

impl HkdfExpander for Sha256Or384Expander<32> {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        expand::<32>(&HMAC_SHA256, &self.prk, info, output)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut buf = [0u8; 32];
        expand::<32>(&HMAC_SHA256, &self.prk, info, &mut buf)
            .expect("expand_block: hash_len fits within RFC 5869 limit");
        let block = OkmBlock::new(&buf);
        buf.zeroize();
        block
    }

    fn hash_len(&self) -> usize {
        32
    }
}

impl HkdfExpander for Sha256Or384Expander<48> {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        expand::<48>(&HMAC_SHA384, &self.prk, info, output)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut buf = [0u8; 48];
        expand::<48>(&HMAC_SHA384, &self.prk, info, &mut buf)
            .expect("expand_block: hash_len fits within RFC 5869 limit");
        let block = OkmBlock::new(&buf);
        buf.zeroize();
        block
    }

    fn hash_len(&self) -> usize {
        48
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 test case 1 (HKDF-SHA-256).
    /// IKM  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
    /// salt = 000102030405060708090a0b0c
    /// info = f0f1f2f3f4f5f6f7f8f9
    /// L    = 42
    /// OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    ///        34007208d5b887185865
    #[test]
    fn hkdf_sha256_rfc5869_case1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let exp = HKDF_SHA256.extract_from_secret(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        exp.expand_slice(&[&info], &mut okm).expect("expand");

        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(okm.as_slice(), expected.as_slice());
    }

    /// RFC 5869 test case 3 (HKDF-SHA-256, empty salt = treated as zeros, empty info).
    /// IKM  = 0b × 22, L = 42
    /// OKM  = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
    ///        9d201395faa4b61a96c8
    #[test]
    fn hkdf_sha256_rfc5869_case3() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let exp = HKDF_SHA256.extract_from_secret(None, &ikm);
        let mut okm = [0u8; 42];
        exp.expand_slice(&[], &mut okm).expect("expand");

        let expected = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .unwrap();
        assert_eq!(okm.as_slice(), expected.as_slice());
    }

    /// HKDF-SHA-384 sanity vector (computed via OpenSSL).
    /// IKM=20×0b, salt=13 bytes 00..0c, info=10 bytes f0..f9, L=42.
    #[test]
    fn hkdf_sha384_basic() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let exp = HKDF_SHA384.extract_from_secret(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        exp.expand_slice(&[&info], &mut okm).expect("expand");

        // Reference computed with `openssl kdf -keylen 42 ...` / Python hkdf.
        let expected = hex::decode(
            "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5",
        )
        .unwrap();
        assert_eq!(okm.as_slice(), expected.as_slice());
    }

    /// Output longer than one hash block must use multiple T(i) iterations.
    #[test]
    fn hkdf_sha256_multiblock() {
        let exp = HKDF_SHA256.extract_from_secret(Some(b"salt"), b"ikm");
        let mut okm = [0u8; 80]; // ~2.5 blocks
        exp.expand_slice(&[b"info"], &mut okm).expect("expand");

        // The first 32 bytes should equal expand_block().
        let block = HKDF_SHA256
            .extract_from_secret(Some(b"salt"), b"ikm")
            .expand_block(&[b"info"]);
        assert_eq!(&okm[..32], block.as_ref());
    }

    /// `extract_from_zero_ikm` must equal `extract_from_secret(salt, &zeros)`
    /// where zeros has length = hash_len. Catches a bug where the wrong
    /// "zero" is passed.
    #[test]
    fn hkdf_sha256_zero_ikm_matches_explicit_zeros() {
        let exp_zero = HKDF_SHA256.extract_from_zero_ikm(Some(b"salt"));
        let exp_explicit = HKDF_SHA256.extract_from_secret(Some(b"salt"), &[0u8; 32]);
        let mut a = [0u8; 40];
        let mut b = [0u8; 40];
        exp_zero.expand_slice(&[b"info"], &mut a).unwrap();
        exp_explicit.expand_slice(&[b"info"], &mut b).unwrap();
        assert_eq!(a, b);
    }

    /// `extract_from_zero_ikm(None)` uses zero salt + zero ikm.
    /// Catches a bug where None-salt path differs across the two extract
    /// methods.
    #[test]
    fn hkdf_sha384_zero_ikm_no_salt_matches_explicit() {
        let exp_zero = HKDF_SHA384.extract_from_zero_ikm(None);
        let exp_explicit = HKDF_SHA384.extract_from_secret(None, &[0u8; 48]);
        let block_a = exp_zero.expand_block(&[b"info"]);
        let block_b = exp_explicit.expand_block(&[b"info"]);
        assert_eq!(block_a.as_ref(), block_b.as_ref());
    }

    /// `expander_for_okm` treats the OkmBlock bytes directly as PRK; the
    /// result must match a hand-computed first HMAC iteration of HKDF-Expand.
    #[test]
    fn hkdf_sha256_expander_for_okm_matches_manual_first_iteration() {
        let okm_bytes = [0x42u8; 32];
        let okm = OkmBlock::new(&okm_bytes);
        let exp = HKDF_SHA256.expander_for_okm(&okm);

        let mut out = [0u8; 32];
        exp.expand_slice(&[b"info"], &mut out).unwrap();

        // RFC 5869 §2.3: T(1) = HMAC(PRK, "" || info || 0x01)
        let mut concat = Vec::from(&b"info"[..]);
        concat.push(0x01);
        let expected = HMAC_SHA256.with_key(&okm_bytes).sign(&[&concat]);
        assert_eq!(&out[..], expected.as_ref());
    }

    /// `hmac_sign(key, msg)` should be the same byte-for-byte as a direct
    /// HMAC call with `key.as_ref()` as the key.
    #[test]
    fn hkdf_sha384_hmac_sign_matches_direct_hmac() {
        let key_bytes = [0xaau8; 48];
        let okm = OkmBlock::new(&key_bytes);
        let tag = HKDF_SHA384.hmac_sign(&okm, b"message");
        let expected = HMAC_SHA384.with_key(&key_bytes).sign(&[b"message"]);
        assert_eq!(tag.as_ref(), expected.as_ref());
    }

    /// `expand_block` must yield exactly `hash_len` bytes equal to the
    /// first hash_len bytes of an `expand_slice` with the same info.
    #[test]
    fn hkdf_sha384_expand_block_equals_truncated_slice() {
        let block = HKDF_SHA384
            .extract_from_secret(Some(b"salt"), b"ikm")
            .expand_block(&[b"info"]);
        let mut slice_out = [0u8; 48];
        HKDF_SHA384
            .extract_from_secret(Some(b"salt"), b"ikm")
            .expand_slice(&[b"info"], &mut slice_out)
            .unwrap();
        assert_eq!(block.as_ref(), &slice_out[..]);
        assert_eq!(block.as_ref().len(), 48);
    }

    /// `hash_len()` accessor must equal the actual block length produced by
    /// `expand_block` — contract verification.
    #[test]
    fn hkdf_hash_len_accessors_match_block_size() {
        let exp_256 = HKDF_SHA256.extract_from_zero_ikm(None);
        assert_eq!(
            exp_256.hash_len(),
            exp_256.expand_block(&[b"x"]).as_ref().len()
        );
        assert_eq!(exp_256.hash_len(), 32);

        let exp_384 = HKDF_SHA384.extract_from_zero_ikm(None);
        assert_eq!(
            exp_384.hash_len(),
            exp_384.expand_block(&[b"x"]).as_ref().len()
        );
        assert_eq!(exp_384.hash_len(), 48);
    }

    /// rustls passes multi-chunk info as `&[&[u8]]`; semantically this must
    /// equal calling expand_slice with a single concatenated chunk.
    #[test]
    fn hkdf_sha256_multi_chunk_info_matches_concatenated() {
        let mut multi = [0u8; 40];
        HKDF_SHA256
            .extract_from_secret(Some(b"salt"), b"ikm")
            .expand_slice(&[b"part-a", b"part-b", b"part-c"], &mut multi)
            .unwrap();
        let mut concat = [0u8; 40];
        HKDF_SHA256
            .extract_from_secret(Some(b"salt"), b"ikm")
            .expand_slice(&[b"part-apart-bpart-c"], &mut concat)
            .unwrap();
        assert_eq!(multi, concat);
    }

    /// FIPS-claim contract.
    #[test]
    fn hkdf_advertises_fips() {
        assert!(HKDF_SHA256.fips());
        assert!(HKDF_SHA384.fips());
    }

    /// L > 255 · HashLen → error.
    #[test]
    fn hkdf_sha256_too_long() {
        let exp = HKDF_SHA256.extract_from_secret(Some(b"salt"), b"ikm");
        let mut okm = vec![0u8; 255 * 32 + 1];
        assert!(exp.expand_slice(&[b"info"], &mut okm).is_err());
    }
}
