use crate::tls::{impl_from_tls, impl_to_tls, FromTlsVec, ToTlsVec};
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
