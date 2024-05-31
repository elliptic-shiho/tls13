use crate::tls::extension_descriptor::{
    KeyShareDescriptor, ServerNameDescriptor, SignatureAlgorithmsDescriptor,
    SupportedGroupsDescriptor, SupportedVersionsDescriptor,
};
use crate::tls::{
    impl_from_tls_with_selector, impl_to_tls, FromTlsVec, FromTlsVecWithSelector, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Extension {
    ServerName(ServerNameDescriptor),
    MaxFragmentLength,
    StatusRequest,
    SupportedGroups(SupportedGroupsDescriptor),
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
    KeyShare(KeyShareDescriptor),
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
            Self::SupportedGroups(desc) => {
                let v = desc.to_tls_vec();
                [10u16.to_tls_vec(), (v.len() as u16).to_tls_vec(), v].concat()
            }
            Self::KeyShare(desc) => {
                let v = desc.to_tls_vec();
                [51u16.to_tls_vec(), (v.len() as u16).to_tls_vec(), v].concat()
            }
            _ => unimplemented!(),
        }
    }
}

impl_from_tls_with_selector! {
    Extension<crate::tls::handshake::ExtensionSelector>(v, selector) {
        let (ext_type, v) = u16::from_tls_vec(v)?;
        let (len, v) = u16::from_tls_vec(v)?;
        let (extension_data, v) = (&v[..(len as usize)], &v[(len as usize)..]);
        Ok(match ext_type {
            0u16 => {
                let (desc, _) = ServerNameDescriptor::from_tls_vec(extension_data)?;
                (Self::ServerName(desc), v)
            }
            13u16 => {
                let (desc, v) = SignatureAlgorithmsDescriptor::from_tls_vec(extension_data)?;
                (Self::SignatureAlgorithms(desc), v)
            }
            43u16 => {
                let (desc, _) = SupportedVersionsDescriptor::from_tls_vec(extension_data, selector)?;
                (Self::SupportedVersions(desc), v)
            }
            10u16 => {
                let (desc, _) = SupportedGroupsDescriptor::from_tls_vec(extension_data)?;
                (Self::SupportedGroups(desc), v)
            }
            51u16 => {
                let (desc, _) = KeyShareDescriptor::from_tls_vec(extension_data, selector)?;
                (Self::KeyShare(desc), v)
            }
            _ => {
                dbg!(ext_type);
                unimplemented!();
            }
        })
    }
}
