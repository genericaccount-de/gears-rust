//! TLS 1.3 cipher suite registrations.
//!
//! Two suites, both FIPS-approved:
//! - `TLS13_AES_128_GCM_SHA256`
//! - `TLS13_AES_256_GCM_SHA384`
//!
//! ChaCha20-Poly1305 is intentionally excluded — it is not FIPS-approved.
//!
//! ## Wire format (RFC 8446 §5.2)
//!
//! - Nonce: 12-byte static IV XORed with big-endian 64-bit sequence number
//!   (zero-padded to 12 bytes), constructed via [`Nonce::new`].
//! - AAD: 5-byte record header `ContentType(0x17) || LegacyVersion(0x0303)
//!   || Length(BE u16)` where length is plaintext + 1 (ContentType) + 16
//!   (tag), constructed via [`make_tls13_aad`].
//! - Inner plaintext: payload + 1 byte ContentType (the actual record type,
//!   not 0x17). The trailing byte distinguishes Handshake/Alert/etc. records.

use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use zeroize::Zeroizing;

use crate::aead;

// =========================================================================
// AEAD algorithm wrappers
// =========================================================================

#[derive(Debug)]
pub struct Aes128Gcm;
#[derive(Debug)]
pub struct Aes256Gcm;

const TAG_LEN: usize = aead::TAG_LEN;

impl Tls13AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter {
            key: Zeroizing::new(key.as_ref().to_vec()),
            iv,
        })
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter {
            key: Zeroizing::new(key.as_ref().to_vec()),
            iv,
        })
    }
    fn key_len(&self) -> usize {
        aead::AES128_KEY_LEN
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

impl Tls13AeadAlgorithm for Aes256Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter {
            key: Zeroizing::new(key.as_ref().to_vec()),
            iv,
        })
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter {
            key: Zeroizing::new(key.as_ref().to_vec()),
            iv,
        })
    }
    fn key_len(&self) -> usize {
        aead::AES256_KEY_LEN
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }
    fn fips(&self) -> bool {
        // Runtime witness — see [`crate::oe::fips_witness_ok`].
        crate::oe::fips_witness_ok()
    }
}

// =========================================================================
// Encrypter / Decrypter
// =========================================================================

struct Tls13Encrypter {
    /// AEAD session key. `Zeroizing` wipes the bytes on drop so the key
    /// does not linger in the heap after the connection closes.
    key: Zeroizing<Vec<u8>>,
    iv: Iv,
}

impl MessageEncrypter for Tls13Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        // Inner plaintext = payload || ContentType (1 byte). RFC 8446 §5.2.
        // `Zeroizing` ensures the cleartext is wiped from the heap after
        // the encrypt call returns.
        let mut pt: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(msg.payload.len() + 1));
        msg.payload.copy_to_vec(&mut pt);
        pt.push(msg.typ.into());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(pt.len() + TAG_LEN);

        let mut ct = vec![0u8; pt.len()];
        let tag = aead::encrypt(&self.key, &nonce.0, aad.as_ref(), &pt, &mut ct)
            .map_err(|e| rustls::Error::General(format!("AES-GCM encrypt: {e}")))?;

        let mut payload = PrefixedPayload::with_capacity(ct.len() + TAG_LEN);
        payload.extend_from_slice(&ct);
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

struct Tls13Decrypter {
    /// AEAD session key. `Zeroizing` wipes the bytes on drop so the key
    /// does not linger in the heap after the connection closes.
    key: Zeroizing<Vec<u8>>,
    iv: Iv,
}

impl MessageDecrypter for Tls13Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_len = msg.payload.len();
        if payload_len < TAG_LEN {
            return Err(rustls::Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload_len);

        let ct_len = payload_len - TAG_LEN;
        // Split: ciphertext | tag (last 16 bytes).
        let payload = &mut msg.payload[..];
        let (ct_buf, tag_buf) = payload.split_at_mut(ct_len);

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(tag_buf);

        // Decrypt into a separate buffer, then copy back. (Apple's GCM may
        // refuse fully aliased in/out; safer to keep them disjoint.)
        // `Zeroizing` wipes the cleartext from this temp on drop.
        let mut pt: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; ct_len]);
        aead::decrypt(&self.key, &nonce.0, aad.as_ref(), ct_buf, &mut pt, &tag)
            .map_err(|_| rustls::Error::DecryptError)?;
        ct_buf.copy_from_slice(&pt);

        // Strip tag from the payload then let rustls strip the TLS 1.3
        // padding + inner ContentType byte.
        msg.payload.truncate(ct_len);
        msg.into_tls13_unpadded_message()
    }
}

// =========================================================================
// Public statics — the AEAD wrappers consumed by `provider::default_provider`.
// =========================================================================

pub static AES_128_GCM: Aes128Gcm = Aes128Gcm;
pub static AES_256_GCM: Aes256Gcm = Aes256Gcm;

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::cipher::OutboundChunks;

    fn aead_key_256() -> AeadKey {
        // rustls's public `AeadKey::from([u8; 32])` always yields a 32-byte
        // key; AES-128 unit-tests aren't expressible at the unit level via
        // public APIs (rustls reserves the shorter variant for its own
        // internal use). AES-128 is exercised end-to-end by handshake_smoke.
        AeadKey::from([0x22u8; 32])
    }
    fn iv12() -> Iv {
        Iv::copy(&[0x33u8; 12])
    }

    /// Encrypted-then-decrypted record must reproduce the original payload
    /// and inner content type. This catches: wrong AAD construction, wrong
    /// nonce derivation from (iv, seq), incorrect tag placement, broken
    /// TLS 1.3 padding/contentType handling on decrypt.
    #[test]
    fn aes256_gcm_record_roundtrip() {
        let mut enc = AES_256_GCM.encrypter(aead_key_256(), iv12());
        let mut dec = AES_256_GCM.decrypter(aead_key_256(), iv12());

        let payload: &[u8] = b"hello tls 1.3 aes-256";
        let msg = OutboundPlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 42).expect("encrypt");

        // Strip the 5-byte TLS record header to get the encrypted payload.
        let wire = opaque.encode();
        assert!(wire.len() > 5 + payload.len() + TAG_LEN);
        let mut body = wire[5..].to_vec();

        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            body.as_mut_slice(),
        );
        let plain = dec.decrypt(inbound, 42).expect("decrypt");
        assert_eq!(plain.payload, payload);
        assert_eq!(plain.typ, ContentType::Handshake);
    }

    /// Wrong sequence number on decrypt must fail tag verification. Catches
    /// a bug where `seq` is not actually folded into the nonce via XOR.
    #[test]
    fn aes256_gcm_wrong_seq_fails() {
        let mut enc = AES_256_GCM.encrypter(aead_key_256(), iv12());
        let mut dec = AES_256_GCM.decrypter(aead_key_256(), iv12());

        let payload: &[u8] = b"x";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 7).expect("encrypt");
        let wire = opaque.encode();
        let mut body = wire[5..].to_vec();

        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            body.as_mut_slice(),
        );
        // Decrypt with seq=0 instead of 7 — must fail (different nonce).
        assert!(dec.decrypt(inbound, 0).is_err());
    }

    /// `extract_keys` returns the appropriate `ConnectionTrafficSecrets`
    /// variant — required for callers exporting keys (e.g. for kTLS or
    /// QUIC interop).
    #[test]
    fn extract_keys_aes128_returns_correct_variant() {
        let secrets = Tls13AeadAlgorithm::extract_keys(&AES_128_GCM, aead_key_256(), iv12())
            .expect("extract");
        assert!(matches!(
            secrets,
            rustls::ConnectionTrafficSecrets::Aes128Gcm { .. }
        ));
    }

    #[test]
    fn extract_keys_aes256_returns_correct_variant() {
        let secrets = Tls13AeadAlgorithm::extract_keys(&AES_256_GCM, aead_key_256(), iv12())
            .expect("extract");
        assert!(matches!(
            secrets,
            rustls::ConnectionTrafficSecrets::Aes256Gcm { .. }
        ));
    }

    /// `key_len()` contract: must match the AES key size for which this
    /// AEAD is registered. A mismatch would cause rustls to derive the
    /// wrong key length from the HKDF schedule.
    #[test]
    fn key_len_contract() {
        assert_eq!(Tls13AeadAlgorithm::key_len(&AES_128_GCM), 16);
        assert_eq!(Tls13AeadAlgorithm::key_len(&AES_256_GCM), 32);
    }

    /// FIPS-claim contract for both AEAD variants.
    #[test]
    fn fips_contract() {
        assert!(Tls13AeadAlgorithm::fips(&AES_128_GCM));
        assert!(Tls13AeadAlgorithm::fips(&AES_256_GCM));
    }

    /// `encrypted_payload_len(N)` exactly equals `N + 1` (inner ContentType
    /// byte) plus `16` (GCM tag). Catches a math drift between this
    /// accessor and the actual `encrypt` output length.
    #[test]
    fn encrypted_payload_len_matches_encrypt_output() {
        let mut enc = AES_256_GCM.encrypter(aead_key_256(), iv12());
        let payload: &[u8] = b"abc";

        let predicted = enc.encrypted_payload_len(payload.len());

        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 0).expect("encrypt");
        let body_len = opaque.encode().len() - 5; // strip record header

        assert_eq!(predicted, body_len);
        assert_eq!(predicted, payload.len() + 1 + TAG_LEN);
    }

    /// Decryption of a too-short payload (< tag size) must error rather than
    /// panic — boundary safety against malformed records.
    #[test]
    fn aes256_gcm_too_short_payload_errors() {
        let mut dec = AES_256_GCM.decrypter(aead_key_256(), iv12());
        let mut buf = [0u8; 5];
        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut buf[..],
        );
        assert!(dec.decrypt(inbound, 0).is_err());
    }
}
