use crate::tls::extension::descriptor::*;
use crate::tls::{
    impl_from_tls_with_selector, impl_to_tls, ExtensionSelector, FromTlsVec,
    FromTlsVecWithSelector, ToTlsVec,
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
    PreSharedKey(PreSharedKeyDescriptor),
    EarlyData,
    SupportedVersions(SupportedVersionsDescriptor),
    Cookie,
    PskKeyExchangeModes(PskKeyExchangeModesDescriptor),
    CertificateAuthorities,
    OidFilters,
    PostHandshakeAuth,
    SignatureAlgorithmsCert,
    KeyShare(KeyShareDescriptor),
    Unknown,
}

impl_to_tls! {
    Extension(self) {
        macro_rules! impl_arm {
            ($name:ident, $n:literal) => {
                {
                    let v = $name.to_tls_vec();
                    [($n as u16).to_tls_vec(), (v.len() as u16).to_tls_vec(), v].concat()
                }
            }
        }
        match self {
            Self::ServerName(desc) => impl_arm!(desc, 0),
            Self::SignatureAlgorithms(desc) => impl_arm!(desc, 13),
            Self::SupportedVersions(desc) => impl_arm!(desc, 43),
            Self::SupportedGroups(desc) => impl_arm!(desc, 10),
            Self::PreSharedKey(desc) => impl_arm!(desc, 41),
            Self::PskKeyExchangeModes(desc) => impl_arm!(desc, 45),
            Self::KeyShare(desc) => impl_arm!(desc, 51),
            _ => unimplemented!(),
        }
    }
}

impl_from_tls_with_selector! {
    Extension<ExtensionSelector>(v, selector) {
        let (ext_type, v) = u16::from_tls_vec(v)?;
        let (len, v) = u16::from_tls_vec(v)?;
        let (extension_data, v) = (&v[..(len as usize)], &v[(len as usize)..]);
        macro_rules! impl_arm {
            ($name:tt, $descriptor:tt) => {
                {
                let (desc, _) = $descriptor::from_tls_vec(extension_data)?;
                (Self::$name(desc), v)
                }
            };
            ($name:tt, $descriptor:tt, $selector:ident) => {
                {
                let (desc, _) = $descriptor::from_tls_vec(extension_data, $selector)?;
                (Self::$name(desc), v)
                }
            };
        }
        Ok(match ext_type {
            0u16 => impl_arm!(ServerName, ServerNameDescriptor),
            13u16 => impl_arm!(SignatureAlgorithms, SignatureAlgorithmsDescriptor),
            43u16 => impl_arm!(SupportedVersions, SupportedVersionsDescriptor, selector),
            10u16 => impl_arm!(SupportedGroups, SupportedGroupsDescriptor),
            41u16 => impl_arm!(PreSharedKey, PreSharedKeyDescriptor, selector),
            45u16 => impl_arm!(PskKeyExchangeModes, PskKeyExchangeModesDescriptor),
            51u16 => impl_arm!(KeyShare, KeyShareDescriptor, selector),
            _ => {
                dbg!(ext_type);
                unimplemented!();
            }
        })
    }
}
