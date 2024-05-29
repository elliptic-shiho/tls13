use crate::tls::extension_descriptor::{
    ServerNameDescriptor, SignatureAlgorithmsDescriptor, SupportedVersionsDescriptor,
};
use crate::tls::{impl_from_tls, impl_to_tls, FromByteVec, ToByteVec};
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
    SupportedVersions(SupportedVersionsDescriptor),
    Cookie,
    PskKeyExchangeModes,
    CertificateAuthorities,
    OidFilters,
    PostHandshakeAuth,
    SignatureAlgorithmsCert,
    KeyShare,
    Unknown,
}

impl_to_tls! {
    Extension(self) {
        match self {
            Self::ServerName(desc) => {
                let v = desc.to_tls_vec();
                [0u16.to_tls_vec(), (v.len() as u16).to_tls_vec(), v].concat()
            }
            Self::SignatureAlgorithms(desc) => {
                let v = desc.to_tls_vec();
                [13u16.to_tls_vec(), (v.len() as u16).to_tls_vec(), v].concat()
            }
            Self::SupportedVersions(desc) => {
                let v = desc.to_tls_vec();
                [43u16.to_tls_vec(), (v.len() as u16).to_tls_vec(), v].concat()
            }
            _ => unimplemented!(),
        }
    }
}

impl_from_tls! {
    Extension(v) {
        let (ext_type, v) = u16::from_tls_vec(v)?;
        let (len, v) = u16::from_tls_vec(v)?;
        let (extension_data, v) = (&v[..(len as usize)], &v[(len as usize)..]);
        Ok(match ext_type {
            0u16 => {
                let (desc, _) = ServerNameDescriptor::from_tls_vec(extension_data)?;
                (Self::ServerName(desc), v)
            }
            13u16 => {
                let (desc, _) = SignatureAlgorithmsDescriptor::from_tls_vec(extension_data)?;
                (Self::SignatureAlgorithms(desc), v)
            }
            43u16 => {
                let (desc, _) = SupportedVersionsDescriptor::from_tls_vec(extension_data)?;
                (Self::SupportedVersions(desc), v)
            }
            _ => unimplemented!(),
        })
    }
}
