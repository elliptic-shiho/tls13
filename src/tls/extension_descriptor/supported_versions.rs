use crate::tls::handshake::ExtensionSelector;
use crate::tls::{
    impl_from_tls_with_selector, impl_to_tls, read_tls_vec_as_vector, write_tls_vec_as_vector,
    FromTlsVec, FromTlsVecWithSelector, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SupportedVersionsDescriptor {
    ClientHello(Vec<u16>),
    ServerHello(u16),
}

impl_to_tls! {
    SupportedVersionsDescriptor(self) {
        match self {
            Self::ClientHello(v) => write_tls_vec_as_vector(v, 1),
            Self::ServerHello(version) => version.to_tls_vec()
        }
    }
}

impl_from_tls_with_selector! {
    SupportedVersionsDescriptor<ExtensionSelector>(v, selector) {
        Ok(match selector {
            ExtensionSelector::ClientHello => {
                let (x, v): (Vec<u16>, &[u8]) = read_tls_vec_as_vector(v, 1)?;
                (Self::ClientHello(x), v)
            }
            ExtensionSelector::ServerHello => {
                let (x, v) = u16::from_tls_vec(v)?;
                (Self::ServerHello(x), v)
            }
            _ => unreachable!()
        })
    }
}
