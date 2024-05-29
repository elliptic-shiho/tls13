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

#[macro_export]
macro_rules! impl_to_tls {
    ($($name:ident ($sel: ident) $bl:block)*) => {
        $(impl ToTlsVec for $name {
            fn to_tls_vec(&$sel) -> Vec<u8>
                $bl
        })*
    }
}

#[macro_export]
macro_rules! impl_from_tls {
    ($($name:ident ($var: ident) $bl:block)*) => {
        $(impl FromTlsVec for $name {
            fn from_tls_vec($var: &[u8]) -> Result<($name, &[u8])>
                $bl
        })*
    }
}

#[macro_export]
macro_rules! impl_from_tls_with_selector {
    ($($name:ident <$type:ty>($var: ident, $selector: ident) $bl:block)*) => {
        $(impl FromTlsVecWithSelector<$type> for $name {
            fn from_tls_vec<'a>($var: &'a [u8], $selector: &$type) -> Result<($name, &'a [u8])>
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

pub fn read_tls_vec_as_vector<T>(v: &[u8], header_size: usize) -> Result<(Vec<T>, &[u8])>
where
    T: FromTlsVec,
{
    let len = match header_size {
        1 => v[0] as usize,
        2 => u16::from_be_bytes([v[0], v[1]]) as usize,
        3 => u32::from_be_bytes([0, v[0], v[1], v[2]]) as usize,
        4 => u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as usize,
        _ => {
            return Err(crate::Error::TlsError(
                format!("Invalid length specified: {}", header_size).to_string(),
            ))
        }
    };

    let mut v = &v[header_size..];
    let mut read_len = 0;
    let mut res = vec![];
    while read_len < len {
        let (elem, t) = T::from_tls_vec(v)?;
        res.push(elem);
        read_len += v.len() - t.len();
        v = t;
    }
    Ok((res, v))
}

pub fn read_tls_vec_as_vector_with_selector<'a, T, S>(
    v: &'a [u8],
    header_size: usize,
    selector: &S,
) -> Result<(Vec<T>, &'a [u8])>
where
    T: FromTlsVecWithSelector<S>,
{
    let len = match header_size {
        1 => v[0] as usize,
        2 => u16::from_be_bytes([v[0], v[1]]) as usize,
        3 => u32::from_be_bytes([0, v[0], v[1], v[2]]) as usize,
        4 => u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as usize,
        _ => {
            return Err(crate::Error::TlsError(
                format!("Invalid length specified: {}", header_size).to_string(),
            ))
        }
    };

    let mut v = &v[header_size..];
    let mut read_len = 0;
    let mut res = vec![];
    while read_len < len {
        let (elem, t) = T::from_tls_vec(v, selector)?;
        res.push(elem);
        read_len += v.len() - t.len();
        v = t;
    }
    Ok((res, v))
}

pub fn write_tls_vec_as_vector<T>(vec: &[T], header_size: usize) -> Vec<u8>
where
    T: ToTlsVec,
{
    if header_size > 4 {
        panic!("Invalid length specified");
    }
    let mut ret = vec![];
    for elem in vec {
        ret.push(elem.to_tls_vec());
    }
    let ret = ret.concat();

    [&(ret.len() as u32).to_tls_vec()[(4 - header_size)..], &ret].concat()
}

pub(crate) use impl_from_tls;
pub(crate) use impl_from_tls_with_selector;
pub(crate) use impl_to_tls;
