use crate::tls::{impl_from_tls, impl_to_tls, FromTlsVec, ToTlsVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(non_camel_case_types)]
pub enum SignatureScheme {
    rsa_pkcs1_sha256,
    rsa_pkcs1_sha384,
    rsa_pkcs1_sha512,
    ecdsa_secp256r1_sha256,
    ecdsa_secp256r1_sha384,
    ecdsa_secp256r1_sha512,
    rsa_pss_rsae_sha256,
    rsa_pss_rsae_sha384,
    rsa_pss_rsae_sha512,
    ed25519,
    ed448,
    rsa_pss_pss_sha256,
    rsa_pss_pss_sha384,
    rsa_pss_pss_sha512,
    rsa_pkcs1_sha1,
    ecdsa_sha1,
    private_use(u16),
}

impl_to_tls! {
    SignatureScheme(self) {
        match self {
            Self::rsa_pkcs1_sha256 => 0x0401,
            Self::rsa_pkcs1_sha384 => 0x0501,
            Self::rsa_pkcs1_sha512 => 0x0601,
            Self::ecdsa_secp256r1_sha256 => 0x0403,
            Self::ecdsa_secp256r1_sha384 => 0x0503,
            Self::ecdsa_secp256r1_sha512 => 0x0603,
            Self::rsa_pss_rsae_sha256 => 0x0804,
            Self::rsa_pss_rsae_sha384 => 0x0805,
            Self::rsa_pss_rsae_sha512 => 0x0806,
            Self::ed25519 => 0x0807,
            Self::ed448 => 0x0808,
            Self::rsa_pss_pss_sha256 => 0x0809,
            Self::rsa_pss_pss_sha384 => 0x080a,
            Self::rsa_pss_pss_sha512 => 0x080b,
            Self::rsa_pkcs1_sha1 => 0x0201,
            Self::ecdsa_sha1 => 0x0203,
            Self::private_use(x) => *x,
        }
        .to_tls_vec()
    }
}

impl_from_tls! {
    SignatureScheme(v) {
        let res = match (v[0], v[1]) {
            (0x04, 0x01) => Self::rsa_pkcs1_sha256,
            (0x05, 0x01) => Self::rsa_pkcs1_sha384,
            (0x06, 0x01) => Self::rsa_pkcs1_sha512,
            (0x04, 0x03) => Self::ecdsa_secp256r1_sha256,
            (0x05, 0x03) => Self::ecdsa_secp256r1_sha384,
            (0x06, 0x03) => Self::ecdsa_secp256r1_sha512,
            (0x08, 0x04) => Self::rsa_pss_rsae_sha256,
            (0x08, 0x05) => Self::rsa_pss_rsae_sha384,
            (0x08, 0x06) => Self::rsa_pss_rsae_sha512,
            (0x08, 0x07) => Self::ed25519,
            (0x08, 0x08) => Self::ed448,
            (0x08, 0x09) => Self::rsa_pss_rsae_sha256,
            (0x08, 0x0a) => Self::rsa_pss_rsae_sha384,
            (0x08, 0x0b) => Self::rsa_pss_rsae_sha512,
            (0x02, 0x01) => Self::rsa_pkcs1_sha1,
            (0x02, 0x03) => Self::ecdsa_sha1,
            (0xfe, x) => Self::private_use(0xfe00u16 + x as u16),
            (0xff, x) => Self::private_use(0xff00u16 + x as u16),
            _ => {
                return Err(crate::Error::TlsError(
                    format!(
                        "Invalid Signature Scheme was specified: {:02x}{:02x}",
                        v[0], v[1]
                    )
                    .to_string(),
                ))
            }
        };
        Ok((res, &v[2..]))
    }
}

impl SignatureScheme {
    pub fn verify(&self, message: &[u8], signature: &[u8], pubkey: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        match self {
            Self::ecdsa_secp256r1_sha256 => {
                let pubkey = p256::PublicKey::from_sec1_bytes(pubkey).unwrap();
                let key = VerifyingKey::from(pubkey);
                let signature = Signature::from_der(signature).unwrap(); // [RFC8446, p.43] Section 4.2.3 "Signature Algorithms"
                key.verify(message, &signature).is_ok()
            }
            _ => {
                unimplemented!()
            }
        }
    }
}
