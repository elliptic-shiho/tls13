use crate::tls::{FromByteVec, ToByteVec};
use crate::Result;

use num_derive::{FromPrimitive, ToPrimitive};

#[allow(non_snake_case, non_camel_case_types)]
#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
}

impl FromByteVec for CipherSuite {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        let (x, v) = u16::from_tls_vec(v)?;
        Ok((
            num_traits::FromPrimitive::from_u16(x)
                .expect("Invalid value specified at CipherSuite::from_tls_vec"),
            v,
        ))
    }
}

impl ToByteVec for CipherSuite {
    fn to_tls_vec(&self) -> Vec<u8> {
        num_traits::ToPrimitive::to_u16(self).unwrap().to_tls_vec()
    }
}
