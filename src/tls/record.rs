use crate::tls::{
    impl_from_tls, impl_to_tls, write_tls_vec_as_vector, Alert, FromTlsVec, Handshake, ToTlsVec,
};
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
    ChangeCipherSpec(Vec<u8>),
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData(Vec<u8>, u64),
}

impl_to_tls! {
    ContentType(self) {
        vec![match self {
            Self::Invalid => 0,
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
        }]
    }

    TlsRecord(self) {
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
            Self::ChangeCipherSpec(data) => {
                let v = write_tls_vec_as_vector(data, 2);
                [
                    ContentType::ChangeCipherSpec.to_tls_vec(), // type
                    0x0303u16.to_tls_vec(),                     // legacy_record_version
                    v,                                          // length / fragment
                ].concat()
            }
            Self::ApplicationData(data, _) => {
                let v = write_tls_vec_as_vector(data, 2);
                [
                    ContentType::ApplicationData.to_tls_vec(), // type
                    0x0303u16.to_tls_vec(),                    // legacy_record_version
                    v,                                         // length / fragment
                ].concat()
            }
        }
    }
}

impl_from_tls! {
    ContentType(v) {
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

impl TlsRecord {
    pub fn parse(v: &[u8], seq_num: u64) -> Result<(Self, &[u8])> {
        let (ctype, v) = ContentType::from_tls_vec(v)?;
        let (_legacy_record_version, v) = u16::from_tls_vec(v)?;
        let (length, v) = u16::from_tls_vec(v)?;
        Ok(match ctype {
            ContentType::Handshake => {
                let (hs, v) = Handshake::from_tls_vec(v)?;
                (Self::Handshake(hs), v)
            }
            ContentType::Alert => {
                let (al, v) = Alert::from_tls_vec(v)?;
                (Self::Alert(al), v)
            }
            ContentType::ChangeCipherSpec => {
                let length = length as usize;
                let (data, v) = (v[..length].to_vec(), &v[length..]);
                (Self::ChangeCipherSpec(data), v)
            }
            ContentType::ApplicationData => {
                let length = length as usize;
                let (encrypted_record, v) = (v[..length].to_vec(), &v[length..]);
                (Self::ApplicationData(encrypted_record, seq_num), v)
            }
            _ => unimplemented!(),
        })
    }

    pub fn parse_inner_plaintext(v: &[u8]) -> Result<Self> {
        let ct = &v[v.len() - 1..];
        if ct == [0u8] {
            return Self::parse_inner_plaintext(v.strip_suffix(&[0]).unwrap());
        }
        let (ctype, _) = ContentType::from_tls_vec(ct).unwrap();
        Ok(match ctype {
            ContentType::Handshake => {
                let (hs, _) = Handshake::from_tls_vec(v)?;
                Self::Handshake(hs)
            }
            ContentType::Alert => {
                let (al, _) = Alert::from_tls_vec(v)?;
                Self::Alert(al)
            }
            x => {
                dbg!(x);
                unimplemented!();
            }
        })
    }

    pub fn get_nonce(&self) -> Vec<u8> {
        match self {
            Self::ApplicationData(_, seq) => seq,
            _ => &0u64,
        }
        .to_be_bytes()
        .to_vec()
    }

    pub fn get_additional_data(&self) -> Vec<u8> {
        self.to_tls_vec()[..5].to_vec()
    }
}
