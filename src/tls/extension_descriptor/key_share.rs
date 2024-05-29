use crate::tls::extension_descriptor::NamedGroup;
use crate::tls::handshake::ExtensionSelector;
use crate::tls::{
    impl_from_tls, impl_from_tls_with_selector, impl_to_tls, read_tls_vec_as_vector,
    write_tls_vec_as_vector, FromTlsVec, FromTlsVecWithSelector, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyShareDescriptor {
    ClientHello(Vec<KeyShareEntry>),
    HelloRetryRequest(NamedGroup),
    ServerHello(KeyShareEntry),
}

impl_to_tls! {
    KeyShareEntry(self) {
        [self.group.to_tls_vec(), write_tls_vec_as_vector(&self.key_exchange, 2)].concat()
    }

    KeyShareDescriptor(self) {
        match self {
            Self::ClientHello(vec) => {
                write_tls_vec_as_vector(vec, 2)
            }
            Self::HelloRetryRequest(ng) => {
                ng.to_tls_vec()
            }
            Self::ServerHello(entry) => {
                entry.to_tls_vec()
            }
        }
    }
}

impl_from_tls! {
    KeyShareEntry(v) {
        let (group, v) = NamedGroup::from_tls_vec(v)?;
        let (key_exchange, v) = read_tls_vec_as_vector(v, 2)?;
        Ok((Self { group, key_exchange }, v))
    }
}

impl_from_tls_with_selector! {
    KeyShareDescriptor<ExtensionSelector>(v, selector) {
        Ok(match selector {
            ExtensionSelector::ClientHello => {
                let (entries, v) = read_tls_vec_as_vector(v, 2)?;
                (Self::ClientHello(entries), v)
            },
            ExtensionSelector::HelloRetryRequest => {
               let (ng, v) = NamedGroup::from_tls_vec(v)?;
               (Self::HelloRetryRequest(ng), v)
            },
            ExtensionSelector::ServerHello => {
                let (entry, v) = KeyShareEntry::from_tls_vec(v)?;
                (Self::ServerHello(entry), v)
            }
        })
    }
}
