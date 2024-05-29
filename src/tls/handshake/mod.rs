mod client_hello;
mod server_hello;

use crate::tls::{impl_from_tls, impl_to_tls, FromTlsVec, ToTlsVec};
use crate::Result;

pub use client_hello::ClientHello;
pub use server_hello::ServerHello;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ExtensionSelector {
    ClientHello,
    ServerHello,
    HelloRetryRequest,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Handshake {
    HelloRequest,
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    CertificateUrl,
    CertificateStatus,
}

impl_to_tls! {
    Handshake(self) {
        match self {
            Self::ClientHello(ch) => {
                let v = ch.to_tls_vec();
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![1u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            Self::ServerHello(sh) => {
                let v = sh.to_tls_vec();
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![2u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            _ => unimplemented!(),
        }
    }
}

impl_from_tls! {
    Handshake(v) {
        let (hs_type, v) = u8::from_tls_vec(v)?;
        match hs_type {
            1u8 => {
                let _len = u32::from_be_bytes([0, v[0], v[1], v[2]]);
                let (ch, v) = ClientHello::from_tls_vec(v)?;
                Ok((Self::ClientHello(ch), v))
            }
            2u8 => {
                let len = u32::from_be_bytes([0, v[0], v[1], v[2]]);
                let v = &v[3..];
                dbg!(len);
                let (sh, v) = ServerHello::from_tls_vec(v)?;
                Ok((Self::ServerHello(sh), v))
            }
            _ => unimplemented!(),
        }
    }
}
