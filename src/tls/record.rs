use crate::tls::{Alert, FromByteVec, Handshake, ToByteVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub enum ContentType {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

// a direct sum structure of TLSPlaintext / TLSCiphertext / TLSInnerPlaintext
#[derive(Debug, PartialEq, Eq)]
pub enum TlsRecord {
    ChangeCipherSpec,
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData(Vec<u8>),
}

impl ToByteVec for ContentType {
    fn to_tls_vec(&self) -> Vec<u8> {
        vec![match self {
            Self::Invalid => 0,
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
        }]
    }
}

impl FromByteVec for ContentType {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        Ok((
            match v[0] {
                0 => Self::Invalid,
                20 => Self::ChangeCipherSpec,
                21 => Self::Alert,
                22 => Self::Handshake,
                23 => Self::ApplicationData,
                _ => {
                    return Err(crate::Error::TlsError(
                        format!("Invalid Content Type: {}", v[0]).to_string(),
                    ))
                }
            },
            &v[1..],
        ))
    }
}

impl ToByteVec for TlsRecord {
    fn to_tls_vec(&self) -> Vec<u8> {
        match self {
            Self::Handshake(hs) => {
                let v = hs.to_tls_vec();
                if v.len() >= 65536 {
                    panic!();
                }
                [
                    ContentType::Handshake.to_tls_vec(), // type
                    0x0303u16.to_tls_vec(),              // legacy_record_version
                    (v.len() as u16).to_tls_vec(),       // length
                    v,                                   // fragment
                ]
                .concat()
            }
            Self::Alert(al) => {
                let v = al.to_tls_vec();
                [
                    ContentType::Alert.to_tls_vec(), // type
                    0x0303u16.to_tls_vec(),          // legacy_record_version
                    (v.len() as u16).to_tls_vec(),   // length
                    v,                               // fragment
                ]
                .concat()
            }
            _ => unimplemented!(),
        }
    }
}

impl FromByteVec for TlsRecord {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        let (ctype, v) = ContentType::from_tls_vec(v)?;
        let (_legacy_record_version, v) = u16::from_tls_vec(v)?;
        let (length, v) = u16::from_tls_vec(v)?;
        dbg!(&ctype);
        Ok(match ctype {
            ContentType::Handshake => {
                let (hs, v) = Handshake::from_tls_vec(v)?;
                (Self::Handshake(hs), v)
            }
            ContentType::Alert => {
                let (al, v) = Alert::from_tls_vec(v)?;
                (Self::Alert(al), v)
            }
            ContentType::ApplicationData => {
                let length = length as usize;
                let (encrypted_record, v) = (v[..length].to_vec(), &v[length..]);
                (Self::ApplicationData(encrypted_record), v)
            }
            _ => unimplemented!(),
        })
    }
}
