//! Signature verification algorithms wired into [`rustls::crypto::WebPkiSupportedAlgorithms`].
//!
//! Each algorithm is a unit struct implementing
//! [`rustls::crypto::SignatureVerificationAlgorithm`]. The trait is invoked
//! by rustls when validating server certificates and the TLS 1.3
//! `CertificateVerify` message.
//!
//! Public-key bytes arrive in their conventional X.509 SPKI subjectPublicKey
//! form:
//! - ECDSA: uncompressed point (`0x04 || X || Y`).
//! - RSA: DER-encoded `RSAPublicKey` (`SEQUENCE { modulus, publicExponent }`).
//!
//! Signature bytes:
//! - ECDSA: DER `ECDSA-Sig-Value { r, s }`.
//! - RSA-PSS, RSA-PKCS#1 v1.5: raw signature bytes.
//!
//! Verification delegates to `SecKey::verify_signature` after importing the
//! public key via [`crate::ffi::security::import_public_key`].

use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::AlgorithmIdentifier;
use rustls::pki_types::InvalidSignature;
use rustls::pki_types::SignatureVerificationAlgorithm;
use rustls::pki_types::alg_id;
use security_framework::key::Algorithm;

use crate::ffi::security::{PublicKeyKind, import_public_key};

// =========================================================================
// Algorithm unit structs
// =========================================================================

#[derive(Debug)]
struct EcdsaP256Sha256;
#[derive(Debug)]
struct EcdsaP384Sha384;
#[derive(Debug)]
struct EcdsaP521Sha512;

#[derive(Debug)]
struct RsaPssSha256;
#[derive(Debug)]
struct RsaPssSha384;
#[derive(Debug)]
struct RsaPssSha512;

#[derive(Debug)]
struct RsaPkcs1Sha256;
#[derive(Debug)]
struct RsaPkcs1Sha384;
#[derive(Debug)]
struct RsaPkcs1Sha512;

// =========================================================================
// SignatureVerificationAlgorithm impls
// =========================================================================

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_with_seckey(
            PublicKeyKind::EcSecPrimeRandomP256,
            Algorithm::ECDSASignatureMessageX962SHA256,
            public_key,
            message,
            signature,
        )
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

impl SignatureVerificationAlgorithm for EcdsaP384Sha384 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_with_seckey(
            PublicKeyKind::EcSecPrimeRandomP384,
            Algorithm::ECDSASignatureMessageX962SHA384,
            public_key,
            message,
            signature,
        )
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P384
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA384
    }
    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

impl SignatureVerificationAlgorithm for EcdsaP521Sha512 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_with_seckey(
            PublicKeyKind::EcSecPrimeRandomP521,
            Algorithm::ECDSASignatureMessageX962SHA512,
            public_key,
            message,
            signature,
        )
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P521
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA512
    }
    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

macro_rules! impl_rsa_pss {
    ($ty:ty, $alg:ident, $sig_alg_id:ident) => {
        impl SignatureVerificationAlgorithm for $ty {
            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                verify_with_seckey(
                    PublicKeyKind::RsaPkcs1,
                    Algorithm::$alg,
                    public_key,
                    message,
                    signature,
                )
            }
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::RSA_ENCRYPTION
            }
            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$sig_alg_id
            }
            fn fips(&self) -> bool {
                // Runtime witness — see [`crate::oe::fips_witness_ok`].
                crate::oe::fips_witness_ok()
            }
        }
    };
}

impl_rsa_pss!(RsaPssSha256, RSASignatureMessagePSSSHA256, RSA_PSS_SHA256);
impl_rsa_pss!(RsaPssSha384, RSASignatureMessagePSSSHA384, RSA_PSS_SHA384);
impl_rsa_pss!(RsaPssSha512, RSASignatureMessagePSSSHA512, RSA_PSS_SHA512);

macro_rules! impl_rsa_pkcs1 {
    ($ty:ty, $alg:ident, $sig_alg_id:ident) => {
        impl SignatureVerificationAlgorithm for $ty {
            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                verify_with_seckey(
                    PublicKeyKind::RsaPkcs1,
                    Algorithm::$alg,
                    public_key,
                    message,
                    signature,
                )
            }
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::RSA_ENCRYPTION
            }
            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$sig_alg_id
            }
            fn fips(&self) -> bool {
                // Runtime witness — see [`crate::oe::fips_witness_ok`].
                crate::oe::fips_witness_ok()
            }
        }
    };
}

impl_rsa_pkcs1!(
    RsaPkcs1Sha256,
    RSASignatureMessagePKCS1v15SHA256,
    RSA_PKCS1_SHA256
);
impl_rsa_pkcs1!(
    RsaPkcs1Sha384,
    RSASignatureMessagePKCS1v15SHA384,
    RSA_PKCS1_SHA384
);
impl_rsa_pkcs1!(
    RsaPkcs1Sha512,
    RSASignatureMessagePKCS1v15SHA512,
    RSA_PKCS1_SHA512
);

// =========================================================================
// Shared verification helper
// =========================================================================

fn verify_with_seckey(
    kind: PublicKeyKind,
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let key = import_public_key(public_key, kind).map_err(|_| InvalidSignature)?;
    match key.verify_signature(algorithm, message, signature) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(InvalidSignature),
    }
}

// =========================================================================
// WebPkiSupportedAlgorithms static
// =========================================================================

static ALL_SIG_ALGS: &[&'static dyn SignatureVerificationAlgorithm] = &[
    &EcdsaP256Sha256,
    &EcdsaP384Sha384,
    &EcdsaP521Sha512,
    &RsaPssSha256,
    &RsaPssSha384,
    &RsaPssSha512,
    &RsaPkcs1Sha256,
    &RsaPkcs1Sha384,
    &RsaPkcs1Sha512,
];

static MAPPING: &[(
    SignatureScheme,
    &[&'static dyn SignatureVerificationAlgorithm],
)] = &[
    (SignatureScheme::ECDSA_NISTP256_SHA256, &[&EcdsaP256Sha256]),
    (SignatureScheme::ECDSA_NISTP384_SHA384, &[&EcdsaP384Sha384]),
    (SignatureScheme::ECDSA_NISTP521_SHA512, &[&EcdsaP521Sha512]),
    (SignatureScheme::RSA_PSS_SHA256, &[&RsaPssSha256]),
    (SignatureScheme::RSA_PSS_SHA384, &[&RsaPssSha384]),
    (SignatureScheme::RSA_PSS_SHA512, &[&RsaPssSha512]),
    (SignatureScheme::RSA_PKCS1_SHA256, &[&RsaPkcs1Sha256]),
    (SignatureScheme::RSA_PKCS1_SHA384, &[&RsaPkcs1Sha384]),
    (SignatureScheme::RSA_PKCS1_SHA512, &[&RsaPkcs1Sha512]),
];

pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: ALL_SIG_ALGS,
    mapping: MAPPING,
};

#[cfg(test)]
mod tests {
    use super::*;
    use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

    fn gen_ec(size_bits: u32) -> SecKey {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec());
        opts.set_size_in_bits(size_bits);
        SecKey::new(&opts).expect("EC keygen")
    }

    fn gen_rsa(size_bits: u32) -> SecKey {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::rsa());
        opts.set_size_in_bits(size_bits);
        SecKey::new(&opts).expect("RSA keygen")
    }

    fn pub_bytes(k: &SecKey) -> Vec<u8> {
        k.public_key()
            .expect("public_key")
            .external_representation()
            .expect("external_representation")
            .bytes()
            .to_vec()
    }

    /// ECDSA P-256 SHA-256 roundtrip: Apple-signed signature must verify
    /// through our trait impl.
    #[test]
    fn ecdsa_p256_sha256_roundtrip() {
        let key = gen_ec(256);
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sig = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        EcdsaP256Sha256.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// ECDSA P-384 SHA-384 roundtrip.
    #[test]
    fn ecdsa_p384_sha384_roundtrip() {
        let key = gen_ec(384);
        let msg = b"another message";
        let sig = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA384, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        EcdsaP384Sha384.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// ECDSA P-521 SHA-512 roundtrip. Required for cross-OS parity
    /// (rustls-cng-crypto on Windows exposes P-521); FIPS-claim unaffected
    /// since Apple corecrypto's CMVP cert covers P-521.
    #[test]
    fn ecdsa_p521_sha512_roundtrip() {
        let key = gen_ec(521);
        let msg = b"p-521 sha-512 roundtrip message";
        let sig = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA512, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        EcdsaP521Sha512.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// Tampered message must fail verification.
    #[test]
    fn ecdsa_p256_tampered_message_fails() {
        let key = gen_ec(256);
        let msg = b"original message";
        let sig = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        let bad = b"different message";
        assert!(EcdsaP256Sha256.verify_signature(&pk, bad, &sig).is_err());
    }

    /// Tampered signature must fail verification.
    #[test]
    fn ecdsa_p256_tampered_signature_fails() {
        let key = gen_ec(256);
        let msg = b"a message";
        let mut sig = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
            .expect("sign");
        // Flip a bit in the signature DER value (avoid the leading SEQUENCE tag).
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        let pk = pub_bytes(&key);
        assert!(EcdsaP256Sha256.verify_signature(&pk, msg, &sig).is_err());
    }

    /// Verification with a DIFFERENT key must fail.
    #[test]
    fn ecdsa_p256_wrong_key_fails() {
        let signer = gen_ec(256);
        let other = gen_ec(256);
        let msg = b"a message";
        let sig = signer
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
            .expect("sign");
        let wrong_pk = pub_bytes(&other);
        assert!(
            EcdsaP256Sha256
                .verify_signature(&wrong_pk, msg, &sig)
                .is_err()
        );
    }

    /// Malformed public-key bytes must fail rather than panic.
    #[test]
    fn ecdsa_p256_malformed_public_key_fails() {
        let bad_pk = vec![0u8; 10];
        let result = EcdsaP256Sha256.verify_signature(&bad_pk, b"msg", b"sig");
        assert!(result.is_err());
    }

    /// RSA-PSS SHA-256 roundtrip.
    #[test]
    fn rsa_pss_sha256_roundtrip() {
        let key = gen_rsa(2048);
        let msg = b"rsa-pss test message";
        let sig = key
            .create_signature(Algorithm::RSASignatureMessagePSSSHA256, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        RsaPssSha256.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// RSA-PSS SHA-384 roundtrip.
    #[test]
    fn rsa_pss_sha384_roundtrip() {
        let key = gen_rsa(2048);
        let msg = b"rsa-pss-384";
        let sig = key
            .create_signature(Algorithm::RSASignatureMessagePSSSHA384, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        RsaPssSha384.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// RSA-PSS SHA-512 roundtrip.
    #[test]
    fn rsa_pss_sha512_roundtrip() {
        let key = gen_rsa(2048);
        let msg = b"rsa-pss-512";
        let sig = key
            .create_signature(Algorithm::RSASignatureMessagePSSSHA512, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        RsaPssSha512.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// RSA-PKCS1 v1.5 SHA-256 roundtrip.
    #[test]
    fn rsa_pkcs1_sha256_roundtrip() {
        let key = gen_rsa(2048);
        let msg = b"rsa-pkcs1-256";
        let sig = key
            .create_signature(Algorithm::RSASignatureMessagePKCS1v15SHA256, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        RsaPkcs1Sha256.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// RSA-PKCS1 v1.5 SHA-384 roundtrip.
    #[test]
    fn rsa_pkcs1_sha384_roundtrip() {
        let key = gen_rsa(2048);
        let msg = b"rsa-pkcs1-384";
        let sig = key
            .create_signature(Algorithm::RSASignatureMessagePKCS1v15SHA384, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        RsaPkcs1Sha384.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// RSA-PKCS1 v1.5 SHA-512 roundtrip.
    #[test]
    fn rsa_pkcs1_sha512_roundtrip() {
        let key = gen_rsa(2048);
        let msg = b"rsa-pkcs1-512";
        let sig = key
            .create_signature(Algorithm::RSASignatureMessagePKCS1v15SHA512, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        RsaPkcs1Sha512.verify_signature(&pk, msg, &sig).unwrap();
    }

    /// Tampered RSA signature must fail.
    #[test]
    fn rsa_pss_sha256_tampered_signature_fails() {
        let key = gen_rsa(2048);
        let msg = b"rsa";
        let mut sig = key
            .create_signature(Algorithm::RSASignatureMessagePSSSHA256, msg)
            .expect("sign");
        sig[0] ^= 0x01;
        let pk = pub_bytes(&key);
        assert!(RsaPssSha256.verify_signature(&pk, msg, &sig).is_err());
    }

    /// Cross-algorithm reject: PKCS#1 v1.5 signature must NOT verify as PSS.
    #[test]
    fn pkcs1_sig_does_not_verify_as_pss() {
        let key = gen_rsa(2048);
        let msg = b"hybrid test";
        let pkcs1_sig = key
            .create_signature(Algorithm::RSASignatureMessagePKCS1v15SHA256, msg)
            .expect("sign");
        let pk = pub_bytes(&key);
        assert!(RsaPssSha256.verify_signature(&pk, msg, &pkcs1_sig).is_err());
    }

    /// Public/signature alg-id pairs match the X.509 OIDs they advertise.
    /// rustls uses these IDs to match TLS sig_alg negotiation with cert
    /// SubjectPublicKeyInfo — a mismatch silently breaks cert validation.
    #[test]
    fn alg_id_contract() {
        assert_eq!(EcdsaP256Sha256.public_key_alg_id(), alg_id::ECDSA_P256);
        assert_eq!(EcdsaP256Sha256.signature_alg_id(), alg_id::ECDSA_SHA256);
        assert_eq!(EcdsaP384Sha384.public_key_alg_id(), alg_id::ECDSA_P384);
        assert_eq!(EcdsaP384Sha384.signature_alg_id(), alg_id::ECDSA_SHA384);
        assert_eq!(EcdsaP521Sha512.public_key_alg_id(), alg_id::ECDSA_P521);
        assert_eq!(EcdsaP521Sha512.signature_alg_id(), alg_id::ECDSA_SHA512);
        assert_eq!(RsaPssSha256.public_key_alg_id(), alg_id::RSA_ENCRYPTION);
        assert_eq!(RsaPssSha256.signature_alg_id(), alg_id::RSA_PSS_SHA256);
        assert_eq!(RsaPkcs1Sha512.signature_alg_id(), alg_id::RSA_PKCS1_SHA512);
    }

    /// All eight algorithms claim FIPS — required for downstream
    /// `ClientConfig::fips()` invariant.
    #[test]
    fn all_algorithms_advertise_fips() {
        for alg in SUPPORTED_SIG_ALGS.all {
            assert!(
                alg.fips(),
                "every supported signature algorithm must advertise FIPS, but {alg:?} does not"
            );
        }
    }

    /// `mapping` table must reference exactly one algorithm per scheme we
    /// advertise. Catches accidental omissions when a new scheme is added.
    #[test]
    fn mapping_table_complete() {
        let schemes_in_mapping: Vec<SignatureScheme> =
            SUPPORTED_SIG_ALGS.mapping.iter().map(|(s, _)| *s).collect();
        let expected = [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ];
        for e in expected {
            assert!(
                schemes_in_mapping.contains(&e),
                "mapping missing scheme {e:?}"
            );
        }
    }
}
