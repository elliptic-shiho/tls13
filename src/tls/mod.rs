use crate::Result;
mod client;
mod crypto;
mod error;
mod extension;
mod handshake;
mod macro_defs;
mod protocol;
mod util;

pub use client::Client;
pub use crypto::CipherSuite;
pub use error::Error;
pub use extension::{Extension, ExtensionSelector};
pub(crate) use macro_defs::{impl_from_tls, impl_from_tls_with_selector, impl_to_tls};
pub use protocol::TlsRecord;
pub use util::{
    read_tls_vec_as_vector, read_tls_vec_as_vector_with_selector, write_tls_vec_as_vector,
};

pub trait ToTlsVec {
    fn to_tls_vec(&self) -> Vec<u8>;
}

pub trait FromTlsVec {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])>
    where
        Self: Sized;
}

pub trait FromTlsVecWithSelector<T> {
    fn from_tls_vec<'a>(v: &'a [u8], selector: &T) -> Result<(Self, &'a [u8])>
    where
        Self: Sized;
}

impl_to_tls! {
    u8(self) {
        vec![*self]
    }

    u16(self) {
        self.to_be_bytes().to_vec()
    }

    u32(self) {
        self.to_be_bytes().to_vec()
    }
}

impl_from_tls! {
    u8(v) {
        Ok((v[0], &v[1..]))
    }

    u16(v) {
        Ok((Self::from_be_bytes([v[0], v[1]]), &v[2..]))
    }

    u32(v) {
        Ok((Self::from_be_bytes([v[0], v[1], v[2], v[3]]), &v[4..]))
    }
}
