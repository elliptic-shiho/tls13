use crate::tls::{impl_from_tls, impl_to_tls, FromTlsVec, ToTlsVec};
use crate::Result;

use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use num_derive::{FromPrimitive, ToPrimitive};
use sha2::{Digest, Sha256, Sha384};

#[allow(non_snake_case, non_camel_case_types)]
#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq, Clone)]
#[repr(u16)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
}

impl_from_tls! {
    CipherSuite(v) {
        let (x, v) = u16::from_tls_vec(v)?;
        Ok((
            num_traits::FromPrimitive::from_u16(x)
                .expect("Invalid value specified at CipherSuite::from_tls_vec"),
            v,
        ))
    }
}

impl_to_tls! {
    CipherSuite(self) {
        num_traits::ToPrimitive::to_u16(self).unwrap().to_tls_vec()
    }
}

impl CipherSuite {
    pub fn hash_length(&self) -> usize {
        match self {
            Self::TLS_AES_256_GCM_SHA384 => 48,
            _ => 32,
        }
    }

    pub fn iv_length(&self) -> usize {
        match self {
            Self::TLS_AES_128_GCM_SHA256 => 12,
            Self::TLS_AES_256_GCM_SHA384 => 12,
            Self::TLS_CHACHA20_POLY1305_SHA256 => 12,
            _ => todo!(),
        }
    }

    pub fn key_length(&self) -> usize {
        match self {
            Self::TLS_AES_128_GCM_SHA256 => 16,
            Self::TLS_AES_256_GCM_SHA384 => 32,
            Self::TLS_CHACHA20_POLY1305_SHA256 => 32,
            _ => todo!(),
        }
    }

    pub fn tag_length(&self) -> usize {
        match self {
            Self::TLS_AES_128_GCM_SHA256 => 16,
            Self::TLS_AES_256_GCM_SHA384 => 16,
            Self::TLS_CHACHA20_POLY1305_SHA256 => 16,
            _ => todo!(),
        }
    }

    pub fn encrypt(&self, key: &[u8], plaintext: &[u8], nonce: &[u8], aad: &[u8]) -> Vec<u8> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        macro_rules! impl_arm {
            ($name:tt) => {{
                let key = Key::<$name>::from_slice(key);
                let cipher = $name::new(key);
                cipher.encrypt(Nonce::from_slice(nonce), payload).unwrap()
            }};
        }

        match self {
            Self::TLS_AES_128_GCM_SHA256 => impl_arm!(Aes128Gcm),
            Self::TLS_AES_256_GCM_SHA384 => impl_arm!(Aes256Gcm),
            Self::TLS_CHACHA20_POLY1305_SHA256 => impl_arm!(ChaCha20Poly1305),
            _ => todo!(),
        }
    }

    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Vec<u8> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        macro_rules! impl_arm {
            ($name:tt) => {{
                let key = Key::<$name>::from_slice(key);
                let cipher = $name::new(key);
                cipher.decrypt(Nonce::from_slice(nonce), payload).unwrap()
            }};
        }

        match self {
            Self::TLS_AES_128_GCM_SHA256 => impl_arm!(Aes128Gcm),
            Self::TLS_AES_256_GCM_SHA384 => impl_arm!(Aes256Gcm),
            Self::TLS_CHACHA20_POLY1305_SHA256 => impl_arm!(ChaCha20Poly1305),
            _ => todo!(),
        }
    }

    pub fn hash(&self, message: Vec<u8>) -> Vec<u8> {
        match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 => {
                let mut hasher = <Sha384 as Digest>::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            _ => {
                let mut hasher = <Sha256 as Digest>::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
        }
    }

    // [RFC8446, p.91] Section 7.1 "Key Schedule"
    pub fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let hkdf_label = [
            (length as u16).to_tls_vec(),
            vec![(6 + label.len()) as u8],
            [b"tls13 ", label.as_bytes()].concat().to_vec(),
            vec![context.len() as u8],
            context.to_vec(),
        ]
        .concat();
        let mut out = vec![0u8; length];

        match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(secret).expect("HKDF initialization");
                hkdf.expand(&hkdf_label, &mut out).expect("HKDF-Expand");
            }
            _ => {
                let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("HKDF initialization");
                hkdf.expand(&hkdf_label, &mut out).expect("HKDF-Expand");
            }
        }
        out
    }

    pub fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 => {
                Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec()
            }
            _ => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
        }
    }

    pub fn hmac(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        match self {
            CipherSuite::TLS_AES_256_GCM_SHA384 => {
                let mut hmac = <Hmac<Sha384> as Mac>::new_from_slice(key).unwrap();
                hmac.update(msg);
                hmac.finalize().into_bytes().to_vec()
            }
            _ => {
                let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
                hmac.update(msg);
                hmac.finalize().into_bytes().to_vec()
            }
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_hkdf_expand_label() {
        // The test vector borrowed from [RFC9001] Section A.1. "Keys"
        use crate::tls::CipherSuite;
        use hex_literal::hex;

        let initial_secret =
            hex!("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
        let client_initial_secret =
            hex!("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        let actual = CipherSuite::TLS_AES_128_GCM_SHA256.hkdf_expand_label(
            &initial_secret,
            "client in",
            &[],
            32,
        );
        assert_eq!(client_initial_secret.to_vec(), actual);
    }
}
