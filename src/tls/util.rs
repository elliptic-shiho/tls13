use crate::tls::{FromTlsVec, FromTlsVecWithSelector, ToTlsVec};
use crate::Result;

pub fn read_tls_vec_as_vector<T>(v: &[u8], header_size: usize) -> Result<(Vec<T>, &[u8])>
where
    T: FromTlsVec,
{
    if v.len() < header_size {
        return Ok((vec![], v));
    }

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
    if v.len() < header_size {
        return Ok((vec![], v));
    }

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
