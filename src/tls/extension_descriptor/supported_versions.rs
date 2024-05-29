use crate::tls::{impl_from_tls, impl_to_tls, FromByteVec, ToByteVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub enum SupportedVersionsDescriptor {
    ClientHello(Vec<u16>),
    ServerHello(u16),
}

impl_to_tls! {
    SupportedVersionsDescriptor(self) {
        match self {
            Self::ClientHello(v) => v.to_tls_vec()[1..].to_vec(),
            Self::ServerHello(version) => version.to_tls_vec()
        }
    }
}

impl_from_tls! {
    SupportedVersionsDescriptor(v) {
        if v.len() > 2 {
            // ClientHello's supported_version field is longer than 4 bytes
            // size(u16) + version[0](u16) + ...
            let (x, v): (Vec<u16>, &[u8]) = Vec::from_tls_vec(v)?;
            Ok((Self::ClientHello(x), v))
        } else {
            let (x, v) = u16::from_tls_vec(v)?;
            Ok((Self::ServerHello(x), v))
        }
    }
}
