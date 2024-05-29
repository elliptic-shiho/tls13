use crate::tls::extension_descriptor::ServerNameDescriptor;
use crate::tls::{FromByteVec, ToByteVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub enum Extension {
    ServerName(ServerNameDescriptor),
    MaxFragmentLength,
    StatusRequest,
    SupportedGroups,
    SignatureAlgorithms,
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
            Self::ServerName(desc) => [0u16.to_tls_vec(), desc.to_tls_vec()].concat(),
            _ => unimplemented!(),
        }
    }
}

impl FromByteVec for Extension {
    fn from_tls_vec(_v: &[u8]) -> Result<(Self, &[u8])> {
        unimplemented!();
    }
}
