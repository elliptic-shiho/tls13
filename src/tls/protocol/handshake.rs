use crate::tls::handshake::{
    Certificate, CertificateVerify, ClientHello, Finished, NewSessionTicket, ServerHello,
};
use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector_with_selector, write_tls_vec_as_vector,
    Extension, ExtensionSelector, FromTlsVec, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Handshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    NewSessionTicket(NewSessionTicket),
    EndOfEarlyData,
    EncryptedExtensions(Vec<Extension>),
    Certificate(Certificate),
    CertificateRequest,
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    KeyUpdate,
    MessageHash,
}

impl_to_tls! {
    Handshake(self) {
        match self {
            Self::ClientHello(ch) => {
                let v = ch.to_tls_vec();
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![1u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            Self::ServerHello(sh) => {
                let v = sh.to_tls_vec();
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![2u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            Self::NewSessionTicket(nst) => {
                let v = nst.to_tls_vec();
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![4u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            Self::EncryptedExtensions(ee) => {
                let v = write_tls_vec_as_vector(ee, 2);
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![8u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            Self::Certificate(cert) => {
                let v = cert.to_tls_vec();
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![11u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            Self::CertificateVerify(cert_verify) => {
                let v = cert_verify.to_tls_vec();
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![15u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            Self::Finished(fin) => {
                let v = fin.to_tls_vec();
                if v.len() >= 16777216 {
                    panic!();
                }
                [vec![20u8], (v.len() as u32).to_tls_vec()[1..].to_vec(), v].concat()
            }
            _ => unimplemented!(),
        }
    }
}

impl_from_tls! {
    Handshake(v) {
        let (hs_type, v) = u8::from_tls_vec(v)?;
        let len = u32::from_be_bytes([0, v[0], v[1], v[2]]) as usize;
        let v = &v[3..];
        match hs_type {
            1u8 => {
                let (ch, _) = ClientHello::from_tls_vec(&v[..len])?;
                Ok((Self::ClientHello(ch), &v[len..]))
            }
            2u8 => {
                let (sh, _) = ServerHello::from_tls_vec(&v[..len])?;
                Ok((Self::ServerHello(sh), &v[len..]))
            },
            4u8 => {
                let (nst, _) = NewSessionTicket::from_tls_vec(&v[..len])?;
                Ok((Self::NewSessionTicket(nst), &v[len..]))
            }
            8u8 => {
                let (ee, _) = read_tls_vec_as_vector_with_selector(&v[..len], 2, &ExtensionSelector::EncryptedExtensions)?;
                Ok((Self::EncryptedExtensions(ee), &v[len..]))
            }
            11u8 => {
                let (cert, _) = Certificate::from_tls_vec(&v[..len])?;
                Ok((Self::Certificate(cert), &v[len..]))
            }
            15u8 => {
                let (cert_verify, _) = CertificateVerify::from_tls_vec(&v[..len])?;
                Ok((Self::CertificateVerify(cert_verify), &v[len..]))
            }
            20u8 => {
                let (finished, _) = Finished::from_tls_vec(&v[..len])?;
                Ok((Self::Finished(finished), &v[len..]))
            }
            _ => {
                dbg!(hs_type);
                unimplemented!();
            }
        }
    }
}
