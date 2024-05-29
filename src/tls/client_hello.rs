use crate::tls::{CipherSuite, Extension, FromByteVec, ToByteVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello {
    legacy_version: u16,
    pub random: Vec<u8>,
    legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    legacy_compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn new(
        random: Vec<u8>,
        cipher_suites: Vec<CipherSuite>,
        extensions: Vec<Extension>,
    ) -> Self {
        Self {
            legacy_version: 0x0303, // Fixed to 0x0303, [RFC8446, p.28]
            random,
            legacy_session_id: vec![], // unpredictable randomly value or zero [RFC8446, p.29]
            cipher_suites,
            legacy_compression_methods: vec![0], // NULL compression (MUST) [RFC8446, p.30]
            extensions,
        }
    }
}

impl FromByteVec for ClientHello {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        let (legacy_version, v) = u16::from_tls_vec(v)?;
        let (random, v): (Vec<u8>, &[u8]) = Vec::from_tls_vec(v)?;
        let (legacy_session_id, v): (Vec<u8>, &[u8]) = Vec::from_tls_vec(v)?;
        let (cipher_suites, v): (Vec<CipherSuite>, &[u8]) = Vec::from_tls_vec(v)?;
        let (legacy_compression_methods, v): (Vec<u8>, &[u8]) = Vec::from_tls_vec(v)?;
        let (extensions, v): (Vec<Extension>, &[u8]) = Vec::from_tls_vec(v)?;
        Ok((
            Self {
                legacy_version,
                random,
                legacy_session_id,
                cipher_suites,
                legacy_compression_methods,
                extensions,
            },
            v,
        ))
    }
}

impl ToByteVec for ClientHello {
    fn to_tls_vec(&self) -> Vec<u8> {
        [
            self.legacy_version.to_tls_vec(),
            self.random.to_tls_vec()[2..].to_vec(),
            self.legacy_session_id.to_tls_vec()[1..].to_vec(),
            self.cipher_suites.to_tls_vec(),
            self.legacy_compression_methods.to_tls_vec()[1..].to_vec(),
            self.extensions.to_tls_vec(),
        ]
        .concat()
    }
}
