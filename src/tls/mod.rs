use crate::Result;
mod alert;
mod cipher_suite;
mod client;
mod client_hello;
mod extension;
pub mod extension_descriptor;
mod handshake;
mod record;

pub use alert::Alert;
pub use cipher_suite::CipherSuite;
pub use client::Client;
pub use client_hello::ClientHello;
pub use extension::Extension;
pub use handshake::Handshake;
pub use record::TlsRecord;

pub trait ToByteVec {
    fn to_tls_vec(&self) -> Vec<u8>;
}

pub trait FromByteVec {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])>
    where
        Self: Sized;
}

#[macro_export]
macro_rules! impl_to_tls {
    ($($name:ident ($sel: ident) $bl:block)*) => {
        $(impl ToByteVec for $name {
            fn to_tls_vec(&$sel) -> Vec<u8>
                $bl
        })*
    }
}

#[macro_export]
macro_rules! impl_from_tls {
    ($($name:ident ($var: ident) $bl:block)*) => {
        $(impl FromByteVec for $name {
            fn from_tls_vec($var: &[u8]) -> Result<($name, &[u8])>
                $bl
        })*
    }
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

    String(self) {
        self.as_bytes().to_vec().to_tls_vec()
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

    String(v) {
        let (b, v): (Vec<u8>, &[u8]) = Vec::from_tls_vec(v)?;
        Ok((
            String::from_utf8(b).expect("Invalid String specified at String::from_tls_vec"),
            v,
        ))
    }
}

impl<T> ToByteVec for Vec<T>
where
    T: ToByteVec,
{
    fn to_tls_vec(&self) -> Vec<u8> {
        let mut ret = vec![];
        for elem in self {
            ret.push(elem.to_tls_vec());
        }
        let ret = ret.concat();
        [(ret.len() as u16).to_tls_vec(), ret].concat()
    }
}

impl<T> FromByteVec for Vec<T>
where
    T: FromByteVec,
{
    fn from_tls_vec(_v: &[u8]) -> Result<(Self, &[u8])> {
        let mut v = _v;
        let len = u16::from_be_bytes([v[0], v[1]]);

        let mut read_len = 0;
        let mut res = vec![];
        while read_len < len {
            let (elem, t) = T::from_tls_vec(v)?;
            res.push(elem);
            read_len += (v.len() - t.len()) as u16;
            v = t;
        }

        Ok((res, v))
    }
}

pub(crate) use impl_from_tls;
pub(crate) use impl_to_tls;
