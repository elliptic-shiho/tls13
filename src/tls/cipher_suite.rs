use crate::tls::{FromByteVec, ToByteVec};
use crate::{Error, Result};

#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_128_CCM_SHA256,
    TLS_AES_128_CCM_8_SHA256,
}

impl FromByteVec for CipherSuite {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        assert!(v.len() >= 2);
        let ret = match (v[0], v[1]) {
            (0x13, 0x01) => Self::TLS_AES_128_GCM_SHA256,
            (0x13, 0x02) => Self::TLS_AES_256_GCM_SHA384,
            (0x13, 0x03) => Self::TLS_CHACHA20_POLY1305_SHA256,
            (0x13, 0x04) => Self::TLS_AES_128_CCM_SHA256,
            (0x13, 0x05) => Self::TLS_AES_128_CCM_8_SHA256,
            _ => {
                return Err(Error::TlsError(
                    format!("Invalid CipherSuite was specified: {:?}", &v[0..2]).to_string(),
                ))
            }
        };
        Ok((ret, &v[2..]))
    }
}

impl ToByteVec for CipherSuite {
    fn to_tls_vec(&self) -> Vec<u8> {
        match &self {
            Self::TLS_AES_128_GCM_SHA256 => [0x13, 0x01],
            Self::TLS_AES_256_GCM_SHA384 => [0x13, 0x02],
            Self::TLS_CHACHA20_POLY1305_SHA256 => [0x13, 0x03],
            Self::TLS_AES_128_CCM_SHA256 => [0x13, 0x04],
            Self::TLS_AES_128_CCM_8_SHA256 => [0x13, 0x05],
        }
        .to_vec()
    }
}
