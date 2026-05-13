//! AES-128-GCM and AES-256-GCM via CommonCrypto's `CCCryptor*` family in
//! `kCCModeGCM`.
//!
//! For TLS we need a 16-byte authentication tag and a 12-byte nonce, which
//! are the AEAD-AES-GCM constants in TLS 1.2 and TLS 1.3. Phase 2 exposes
//! standalone `encrypt` / `decrypt` functions; Phase 4 wraps them in the
//! `Tls13AeadAlgorithm` / `Tls12AeadAlgorithm` traits.

use core::ffi::c_void;
use core::ptr;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::ffi::commoncrypto as cc;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const AES128_KEY_LEN: usize = 16;
pub const AES256_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("CommonCrypto returned status {0}")]
    CommonCrypto(cc::CCCryptorStatus),
    #[error("output buffer too small (need {needed}, have {have})")]
    OutputTooSmall { needed: usize, have: usize },
    #[error("invalid key length {0} (must be 16 or 32)")]
    InvalidKeyLen(usize),
    #[error("invalid nonce length {0} (must be 12)")]
    InvalidNonceLen(usize),
    #[error("authentication tag mismatch (ciphertext tampered or wrong key)")]
    TagMismatch,
}

/// RAII wrapper for `CCCryptorRef` that releases on drop.
struct Cryptor(cc::CCCryptorRef);

impl Drop for Cryptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was produced by `CCCryptorCreateWithMode`; releasing
            // a valid cryptor is always safe and idempotent w.r.t. our state.
            unsafe {
                cc::CCCryptorRelease(self.0);
            }
        }
    }
}

fn create_cryptor(op: cc::CCOperation, key: &[u8], iv: &[u8]) -> Result<Cryptor, AeadError> {
    if key.len() != AES128_KEY_LEN && key.len() != AES256_KEY_LEN {
        return Err(AeadError::InvalidKeyLen(key.len()));
    }
    if iv.len() != NONCE_LEN {
        return Err(AeadError::InvalidNonceLen(iv.len()));
    }
    let mut cryptor: cc::CCCryptorRef = ptr::null_mut();
    // SAFETY: All pointers are correctly typed and lifetimes outlast the call.
    // The IV is set via CCCryptorGCMAddIV after Create — passing it inside
    // Create produced inconsistent results across CommonCrypto revisions.
    let status = unsafe {
        cc::CCCryptorCreateWithMode(
            op,
            cc::kCCModeGCM,
            cc::kCCAlgorithmAES,
            cc::ccNoPadding,
            ptr::null(), // IV set via CCCryptorGCMAddIV below
            key.as_ptr() as *const c_void,
            key.len(),
            ptr::null(), // no tweak (XTS only)
            0,
            0, // num_rounds: 0 = default
            0, // options
            &mut cryptor,
        )
    };
    if status != cc::kCCSuccess {
        return Err(AeadError::CommonCrypto(status));
    }
    // SAFETY: cryptor is valid and freshly created; iv length is checked above.
    let s = unsafe { cc::CCCryptorGCMAddIV(cryptor, iv.as_ptr() as *const c_void, iv.len()) };
    if s != cc::kCCSuccess {
        // SAFETY: cryptor was allocated; release it before returning the error.
        unsafe {
            cc::CCCryptorRelease(cryptor);
        }
        return Err(AeadError::CommonCrypto(s));
    }
    Ok(Cryptor(cryptor))
}

fn add_aad(c: &Cryptor, aad: &[u8]) -> Result<(), AeadError> {
    if aad.is_empty() {
        return Ok(());
    }
    // SAFETY: cryptor is valid; aad is a valid slice.
    let s = unsafe { cc::CCCryptorGCMaddAAD(c.0, aad.as_ptr() as *const c_void, aad.len()) };
    if s != cc::kCCSuccess {
        return Err(AeadError::CommonCrypto(s));
    }
    Ok(())
}

fn run_update(c: &Cryptor, input: &[u8], output: &mut [u8]) -> Result<(), AeadError> {
    if output.len() < input.len() {
        return Err(AeadError::OutputTooSmall {
            needed: input.len(),
            have: output.len(),
        });
    }
    if input.is_empty() {
        return Ok(());
    }
    let mut moved: usize = 0;
    // SAFETY: pointers and lengths are correct.
    let s = unsafe {
        cc::CCCryptorUpdate(
            c.0,
            input.as_ptr() as *const c_void,
            input.len(),
            output.as_mut_ptr() as *mut c_void,
            output.len(),
            &mut moved,
        )
    };
    if s != cc::kCCSuccess {
        return Err(AeadError::CommonCrypto(s));
    }
    // GCM is a stream cipher: `moved` must equal input.len() byte-for-byte.
    // If CommonCrypto ever returns a short write the trailing bytes of
    // `output` are uninitialised; we must NOT return Ok in that case.
    if moved != input.len() {
        return Err(AeadError::CommonCrypto(cc::kCCUnspecifiedError));
    }
    Ok(())
}

fn finalize_tag(c: &Cryptor) -> Result<[u8; TAG_LEN], AeadError> {
    let mut tag = [0u8; TAG_LEN];
    let mut tag_len = TAG_LEN;
    // SAFETY: tag and tag_len are valid pointers to writable memory.
    // CCCryptorGCMFinal finalizes the GCM state and writes the (computed) tag.
    let s = unsafe { cc::CCCryptorGCMFinal(c.0, tag.as_mut_ptr() as *mut c_void, &mut tag_len) };
    if s != cc::kCCSuccess {
        return Err(AeadError::CommonCrypto(s));
    }
    if tag_len != TAG_LEN {
        return Err(AeadError::CommonCrypto(cc::kCCParamError));
    }
    Ok(tag)
}

/// Encrypt `plaintext` into `ciphertext_out`, returning the 16-byte tag.
///
/// `key` must be 16 or 32 bytes; `iv` exactly 12 bytes;
/// `ciphertext_out.len() >= plaintext.len()` (extra space is untouched).
pub fn encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<[u8; TAG_LEN], AeadError> {
    let c = create_cryptor(cc::kCCEncrypt, key, iv)?;
    add_aad(&c, aad)?;
    run_update(&c, plaintext, ciphertext_out)?;
    finalize_tag(&c)
}

/// Decrypt `ciphertext` into `plaintext_out`, verifying `expected_tag`.
///
/// On tag mismatch the output buffer's contents are *unspecified* (typically
/// the speculatively-decrypted plaintext); callers must treat the entire
/// output as compromised and not use it. We zeroize the output on mismatch
/// as a defense-in-depth measure.
///
/// Callers that hold the resulting plaintext in their own buffer should wrap
/// it in `zeroize::Zeroizing` so the cleartext is wiped on drop — both the
/// TLS 1.3 and TLS 1.2 wrappers in this crate already do that.
pub fn decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
    expected_tag: &[u8; TAG_LEN],
) -> Result<(), AeadError> {
    let c = create_cryptor(cc::kCCDecrypt, key, iv)?;
    add_aad(&c, aad)?;
    run_update(&c, ciphertext, plaintext_out)?;
    let computed = finalize_tag(&c)?;
    if computed.ct_eq(expected_tag).into() {
        Ok(())
    } else {
        // Wipe the speculatively-decrypted plaintext.
        plaintext_out[..ciphertext.len()].zeroize();
        Err(AeadError::TagMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST GCM CAVS Test Case 13 (AES-128-GCM, 96-bit IV).
    /// Key:   feffe9928665731c6d6a8f9467308308
    /// IV:    cafebabefacedbaddecaf888
    /// PT:    d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
    /// AAD:   feedfacedeadbeeffeedfacedeadbeefabaddad2
    /// CT:    42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091
    /// Tag:   5bc94fbc3221a5db94fae95ae7121a47
    #[test]
    fn aes128_gcm_nist_case13() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let pt = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let ct_expected = hex::decode(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        )
        .unwrap();
        let tag_expected = hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap();

        let mut ct = vec![0u8; pt.len()];
        let tag = encrypt(&key, &iv, &aad, &pt, &mut ct).expect("encrypt");
        assert_eq!(ct, ct_expected);
        assert_eq!(tag.as_slice(), tag_expected.as_slice());

        // Roundtrip
        let mut pt_back = vec![0u8; ct.len()];
        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(&tag_expected);
        decrypt(&key, &iv, &aad, &ct, &mut pt_back, &tag_arr).expect("decrypt");
        assert_eq!(pt_back, pt);
    }

    /// NIST GCM CAVS Test Case 16 (AES-256-GCM, 96-bit IV).
    /// Key:   feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
    /// IV:    cafebabefacedbaddecaf888
    /// PT:    d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
    /// AAD:   feedfacedeadbeeffeedfacedeadbeefabaddad2
    /// CT:    522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662
    /// Tag:   76fc6ece0f4e1768cddf8853bb2d551b
    #[test]
    fn aes256_gcm_nist_case16() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let pt = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let ct_expected = hex::decode(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        )
        .unwrap();
        let tag_expected = hex::decode("76fc6ece0f4e1768cddf8853bb2d551b").unwrap();

        let mut ct = vec![0u8; pt.len()];
        let tag = encrypt(&key, &iv, &aad, &pt, &mut ct).expect("encrypt");
        assert_eq!(ct, ct_expected);
        assert_eq!(tag.as_slice(), tag_expected.as_slice());

        let mut pt_back = vec![0u8; ct.len()];
        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(&tag_expected);
        decrypt(&key, &iv, &aad, &ct, &mut pt_back, &tag_arr).expect("decrypt");
        assert_eq!(pt_back, pt);
    }

    /// Empty plaintext + empty AAD case (NIST GCM Test Case 1, AES-128).
    /// Key=00..., IV=00..., Tag=58e2fccefa7e3061367f1d57a4e7455a.
    #[test]
    fn aes128_gcm_nist_case1_empty() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let aad: &[u8] = &[];
        let pt: &[u8] = &[];
        let mut ct = [0u8; 0];
        let tag = encrypt(&key, &iv, aad, pt, &mut ct).expect("encrypt");
        let expected = hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap();
        assert_eq!(tag.as_slice(), expected.as_slice());

        let mut pt_back = [0u8; 0];
        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(&expected);
        decrypt(&key, &iv, aad, &ct, &mut pt_back, &tag_arr).expect("decrypt");
    }

    /// Tampered ciphertext must fail authentication.
    #[test]
    fn aes128_gcm_tampered_ct_fails() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let pt = b"hello world";
        let aad = b"context";

        let mut ct = vec![0u8; pt.len()];
        let tag = encrypt(&key, &iv, aad, pt, &mut ct).expect("encrypt");

        // Flip one bit in ciphertext.
        ct[0] ^= 0x01;
        let mut pt_back = vec![0u8; ct.len()];
        let err = decrypt(&key, &iv, aad, &ct, &mut pt_back, &tag).unwrap_err();
        assert!(matches!(err, AeadError::TagMismatch), "got {err:?}");
        // Speculatively-decrypted output must be wiped.
        assert!(pt_back.iter().all(|&b| b == 0));
    }

    /// Tampered tag must fail authentication.
    #[test]
    fn aes128_gcm_tampered_tag_fails() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let pt = b"hello world";
        let aad: &[u8] = &[];

        let mut ct = vec![0u8; pt.len()];
        let mut tag = encrypt(&key, &iv, aad, pt, &mut ct).expect("encrypt");

        tag[0] ^= 0xff;
        let mut pt_back = vec![0u8; ct.len()];
        let err = decrypt(&key, &iv, aad, &ct, &mut pt_back, &tag).unwrap_err();
        assert!(matches!(err, AeadError::TagMismatch), "got {err:?}");
    }

    /// Tampered AAD must fail authentication.
    #[test]
    fn aes128_gcm_tampered_aad_fails() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let pt = b"hello world";

        let mut ct = vec![0u8; pt.len()];
        let tag = encrypt(&key, &iv, b"correct-aad", pt, &mut ct).expect("encrypt");

        let mut pt_back = vec![0u8; ct.len()];
        let err = decrypt(&key, &iv, b"wrong-aad", &ct, &mut pt_back, &tag).unwrap_err();
        assert!(matches!(err, AeadError::TagMismatch), "got {err:?}");
    }

    /// Invalid key length must error before touching CommonCrypto.
    #[test]
    fn aes_gcm_invalid_key_len() {
        let key = [0u8; 24]; // AES-192 not supported (TLS doesn't use it)
        let iv = [0u8; 12];
        let mut ct = [0u8; 0];
        let err = encrypt(&key, &iv, &[], &[], &mut ct).unwrap_err();
        assert!(matches!(err, AeadError::InvalidKeyLen(24)), "got {err:?}");
    }

    /// Decryption with the wrong key must fail tag verification (not return
    /// garbled plaintext). This is the core AEAD authenticity guarantee.
    #[test]
    fn aes128_gcm_wrong_key_fails_auth() {
        let key_enc = [0x11u8; 16];
        let key_dec = [0x22u8; 16];
        let iv = [0x33u8; 12];
        let pt = b"hello world";

        let mut ct = vec![0u8; pt.len()];
        let tag = encrypt(&key_enc, &iv, &[], pt, &mut ct).expect("encrypt");

        let mut pt_back = vec![0u8; ct.len()];
        let err = decrypt(&key_dec, &iv, &[], &ct, &mut pt_back, &tag).unwrap_err();
        assert!(matches!(err, AeadError::TagMismatch));
        // Speculative output wiped.
        assert!(pt_back.iter().all(|&b| b == 0));
    }

    /// Decryption with the wrong IV must fail tag verification.
    #[test]
    fn aes128_gcm_wrong_iv_fails_auth() {
        let key = [0x11u8; 16];
        let iv_enc = [0x33u8; 12];
        let iv_dec = [0x44u8; 12];
        let pt = b"hello world";

        let mut ct = vec![0u8; pt.len()];
        let tag = encrypt(&key, &iv_enc, &[], pt, &mut ct).expect("encrypt");

        let mut pt_back = vec![0u8; ct.len()];
        let err = decrypt(&key, &iv_dec, &[], &ct, &mut pt_back, &tag).unwrap_err();
        assert!(matches!(err, AeadError::TagMismatch));
    }

    /// `output_too_small` is enforced *before* any FFI call. Catches a bug
    /// where the size check is removed and CommonCrypto writes out of bounds.
    #[test]
    fn aes_gcm_output_too_small_errors_early() {
        let mut ct = vec![0u8; 5];
        let err = encrypt(&[0u8; 16], &[0u8; 12], &[], b"hello world", &mut ct)
            .expect_err("must reject undersized output");
        match err {
            AeadError::OutputTooSmall { needed, have } => {
                assert_eq!(needed, 11);
                assert_eq!(have, 5);
            }
            other => panic!("expected OutputTooSmall, got {other:?}"),
        }
        // The undersized buffer must NOT be touched by CommonCrypto.
        assert!(ct.iter().all(|&b| b == 0));
    }

    /// AAD-only authenticate-only-no-encrypt: empty plaintext, non-empty AAD.
    /// Tag must depend on AAD; modifying AAD on decrypt must fail.
    #[test]
    fn aes128_gcm_aad_only_roundtrip_and_aad_dependency() {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 12];
        let aad = b"authenticated-only-data";
        let mut ct = [0u8; 0];

        let tag = encrypt(&key, &iv, aad, &[], &mut ct).expect("encrypt");

        // Verify with correct AAD.
        let mut pt_back = [0u8; 0];
        decrypt(&key, &iv, aad, &ct, &mut pt_back, &tag).expect("decrypt");

        // Tampering AAD must break auth.
        let err = decrypt(&key, &iv, b"different-aad", &ct, &mut pt_back, &tag).unwrap_err();
        assert!(matches!(err, AeadError::TagMismatch));
    }

    /// Multi-block plaintext (1 KiB across 64 AES blocks) must roundtrip
    /// intact. Exercises CCCryptorUpdate's internal chunking and confirms
    /// that ciphertext is genuinely different from plaintext.
    #[test]
    fn aes256_gcm_long_plaintext_roundtrip() {
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let pt: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let aad = b"context";

        let mut ct = vec![0u8; pt.len()];
        let tag = encrypt(&key, &iv, aad, &pt, &mut ct).expect("encrypt");
        assert_ne!(ct, pt, "ciphertext must differ from plaintext");

        let mut pt_back = vec![0u8; ct.len()];
        decrypt(&key, &iv, aad, &ct, &mut pt_back, &tag).expect("decrypt");
        assert_eq!(pt, pt_back);
    }

    /// Confidentiality with empty AAD: same plaintext under two different
    /// keys must produce different ciphertexts.
    #[test]
    fn aes128_gcm_different_keys_give_different_ciphertexts() {
        let iv = [0u8; 12];
        let pt = b"shared plaintext";
        let mut ct_a = vec![0u8; pt.len()];
        let mut ct_b = vec![0u8; pt.len()];
        encrypt(&[0x11u8; 16], &iv, &[], pt, &mut ct_a).expect("a");
        encrypt(&[0x22u8; 16], &iv, &[], pt, &mut ct_b).expect("b");
        assert_ne!(ct_a, ct_b);
    }

    /// Invalid nonce length must error.
    #[test]
    fn aes_gcm_invalid_nonce_len() {
        let key = [0u8; 16];
        let iv = [0u8; 13];
        let mut ct = [0u8; 0];
        let err = encrypt(&key, &iv, &[], &[], &mut ct).unwrap_err();
        assert!(matches!(err, AeadError::InvalidNonceLen(13)), "got {err:?}");
    }
}
