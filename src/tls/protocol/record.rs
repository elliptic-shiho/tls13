use crate::tls::protocol::{Alert, Handshake};
use crate::tls::{impl_from_tls, impl_to_tls, write_tls_vec_as_vector, FromTlsVec, ToTlsVec};
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TlsRecord {
    ChangeCipherSpec(Vec<u8>, u64),
    Alert(Alert, u64),
    Handshake(Handshake, u64),
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
            Self::Handshake(hs, _) => {
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
            Self::Alert(al, _) => {
                let v = al.to_tls_vec();
                [
                    ContentType::Alert.to_tls_vec(), // type
                    0x0303u16.to_tls_vec(),          // legacy_record_version
                    (v.len() as u16).to_tls_vec(),   // length
                    v,                               // fragment
                ]
                .concat()
            }
            Self::ChangeCipherSpec(data, _) => {
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
        assert!((length as i32) < (256 + (1 << 14)));
        assert!(v.len() >= length as usize);
        Ok(match ctype {
            ContentType::Handshake => {
                let (hs, v) = Handshake::from_tls_vec(v)?;
                (Self::Handshake(hs, 0), v)
            }
            ContentType::Alert => {
                let (al, v) = Alert::from_tls_vec(v)?;
                (Self::Alert(al, 0), v)
            }
            ContentType::ChangeCipherSpec => {
                let length = length as usize;
                let (data, v) = (v[..length].to_vec(), &v[length..]);
                (Self::ChangeCipherSpec(data, 0), v)
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
        let ct = v[v.len() - 1];
        if ct == 0u8 {
            return Self::parse_inner_plaintext(v.strip_suffix(&[0]).unwrap());
        }
        let (ctype, _) = ContentType::from_tls_vec(&[ct]).unwrap();
        let v = &v[..v.len() - 1];
        Ok(match ctype {
            ContentType::Handshake => {
                let (hs, _) = Handshake::from_tls_vec(v)?;
                Self::Handshake(hs, 0)
            }
            ContentType::Alert => {
                let (al, _) = Alert::from_tls_vec(v)?;
                Self::Alert(al, 0)
            }
            ContentType::ApplicationData => Self::ApplicationData(v.to_vec(), 0),
            x => {
                dbg!(x);
                unimplemented!();
            }
        })
    }

    pub fn unparse_inner_plaintext(&self) -> Vec<u8> {
        let tls_vec = self.to_tls_vec();
        [tls_vec[5..].to_vec(), vec![tls_vec[0]]].concat()
    }

    pub fn get_additional_data(&self) -> Vec<u8> {
        self.to_tls_vec()[..5].to_vec()
    }

    pub fn get_sequence_number(&self) -> u64 {
        match self {
            Self::ApplicationData(_, seq) => *seq,
            Self::ChangeCipherSpec(_, seq) => *seq,
            Self::Alert(_, seq) => *seq,
            Self::Handshake(_, seq) => *seq,
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_unparse_inner_plaintext() {
        use crate::tls::TlsRecord;
        let record = TlsRecord::ApplicationData(b"test".to_vec(), 0);
        assert_eq!(
            record.unparse_inner_plaintext(),
            vec![0x74, 0x65, 0x73, 0x74, 23]
        );
    }

    #[test]
    fn test_parse_inner_plaintext() {
        use crate::tls::TlsRecord;
        let record = TlsRecord::ApplicationData(b"test".to_vec(), 0);
        let v = vec![0x74, 0x65, 0x73, 0x74, 23];
        assert_eq!(TlsRecord::parse_inner_plaintext(&v).unwrap(), record);
    }
}
