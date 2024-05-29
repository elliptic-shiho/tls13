use crate::tls::{impl_from_tls, impl_to_tls, ClientHello, FromByteVec, ToByteVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub enum Handshake {
    HelloRequest,
    ClientHello(ClientHello),
    ServerHello,
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
            _ => unimplemented!(),
        }
    }
}

impl_from_tls! {
    Handshake(v) {
        match v[0] {
            1 => {
                let (_len, v) = u16::from_tls_vec(&v[1..])?;
                let (ch, v) = ClientHello::from_tls_vec(v)?;
                Ok((Self::ClientHello(ch), v))
            }
            _ => unimplemented!(),
        }
    }
}
