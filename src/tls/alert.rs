use crate::tls::{FromByteVec, ToByteVec};
use crate::Result;

use num_derive::{FromPrimitive, ToPrimitive};

#[derive(Debug, PartialEq, Eq)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

impl FromByteVec for AlertLevel {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        let (x, v) = u8::from_tls_vec(v)?;
        Ok((
            num_traits::FromPrimitive::from_u8(x)
                .expect("Invalid value specified at AlertLevel::from_tls_vec"),
            v,
        ))
    }
}

impl ToByteVec for AlertLevel {
    fn to_tls_vec(&self) -> Vec<u8> {
        num_traits::ToPrimitive::to_u8(self).unwrap().to_tls_vec()
    }
}

impl FromByteVec for AlertDescription {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        let (x, v) = u8::from_tls_vec(v)?;
        Ok((
            num_traits::FromPrimitive::from_u8(x)
                .expect("Invalid value specified at Description::from_tls_vec"),
            v,
        ))
    }
}

impl ToByteVec for AlertDescription {
    fn to_tls_vec(&self) -> Vec<u8> {
        num_traits::ToPrimitive::to_u8(self).unwrap().to_tls_vec()
    }
}

impl FromByteVec for Alert {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        let (level, v) = AlertLevel::from_tls_vec(v)?;
        let (description, v) = AlertDescription::from_tls_vec(v)?;
        Ok((Alert { level, description }, v))
    }
}

impl ToByteVec for Alert {
    fn to_tls_vec(&self) -> Vec<u8> {
        [self.level.to_tls_vec(), self.description.to_tls_vec()].concat()
    }
}
