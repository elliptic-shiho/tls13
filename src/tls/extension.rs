use crate::tls::extension_descriptor::{ServerNameDescriptor, SignatureAlgorithmsDescriptor};
use crate::tls::{FromByteVec, ToByteVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub enum Extension {
    ServerName(ServerNameDescriptor),
    MaxFragmentLength,
    StatusRequest,
    SupportedGroups,
    SignatureAlgorithms(SignatureAlgorithmsDescriptor),
    UseStrp,
    Heartbeat,
    ApplicationLayerProtocolNegotiation,
    SignedCertificateTimestamp,
    ClientCertificateType,
    ServerCertificateType,
    Padding,
    PreSharedKey,
    EarlyData,
    SupportedVersions,
    Cookie,
    PskKeyExchangeModes,
    CertificateAuthorities,
    OidFilters,
    PostHandshakeAuth,
    SignatureAlgorithmsCert,
    KeyShare,
    Unknown,
}

impl ToByteVec for Extension {
    fn to_tls_vec(&self) -> Vec<u8> {
        match self {
            Self::ServerName(desc) => {
                let v = desc.to_tls_vec();
                [0u16.to_tls_vec(), (v.len() as u16).to_tls_vec(), v].concat()
            }
            Self::SignatureAlgorithms(desc) => {
                let v = desc.to_tls_vec();
                [13u16.to_tls_vec(), (v.len() as u16).to_tls_vec(), v].concat()
            }
            _ => unimplemented!(),
        }
    }
}

impl FromByteVec for Extension {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        let (ext_type, v) = u16::from_tls_vec(v)?;
        Ok(match ext_type {
            0u16 => {
                let (_len, v) = u16::from_tls_vec(v)?;
                let (desc, v) = ServerNameDescriptor::from_tls_vec(v)?;
                (Self::ServerName(desc), v)
            }
            13u16 => {
                let (_len, v) = u16::from_tls_vec(v)?;
                let (desc, v) = SignatureAlgorithmsDescriptor::from_tls_vec(v)?;
                (Self::SignatureAlgorithms(desc), v)
            }
            _ => unimplemented!(),
        })
    }
}
