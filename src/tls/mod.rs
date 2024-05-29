use crate::Result;
mod cipher_suite;
mod client;
mod client_hello;
mod extension;

pub use cipher_suite::CipherSuite;
pub use client::Client;
pub use client_hello::ClientHello;
pub use extension::Extension;

pub trait ToByteVec {
    fn to_tls_vec(&self) -> Vec<u8>;
}

pub trait FromByteVec {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])>
    where
        Self: Sized;
}

impl ToByteVec for u8 {
    fn to_tls_vec(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl FromByteVec for u8 {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        Ok((v[0], &v[1..]))
    }
}

impl ToByteVec for u16 {
    fn to_tls_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl FromByteVec for u16 {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        Ok((Self::from_be_bytes([v[0], v[1]]), &v[2..]))
    }
}

impl ToByteVec for u32 {
    fn to_tls_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl FromByteVec for u32 {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        Ok((Self::from_be_bytes([v[0], v[1], v[2], v[3]]), &v[4..]))
    }
}

impl<T> ToByteVec for Vec<T>
where
    T: ToByteVec,
{
    fn to_tls_vec(&self) -> Vec<u8> {
        if self.len() >= 16384 {
            panic!();
        }
        let mut ret = vec![];
        ret.push((self.len() as u16).to_tls_vec());
        for elem in self {
            ret.push(elem.to_tls_vec());
        }
        ret.concat()
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
