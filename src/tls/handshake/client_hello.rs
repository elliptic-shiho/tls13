use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, read_tls_vec_as_vector_with_selector,
    write_tls_vec_as_vector, CipherSuite, Extension, ExtensionSelector, FromTlsVec, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
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

impl_from_tls! {
    ClientHello(v) {
        let (legacy_version, v) = u16::from_tls_vec(v)?;
        let (random, v) = (v[..32].to_vec(), &v[32..]);
        let (legacy_session_id, v) = read_tls_vec_as_vector(v, 1)?;
        let (cipher_suites, v) = read_tls_vec_as_vector(v, 2)?;
        let (legacy_compression_methods, v) = read_tls_vec_as_vector(v, 1)?;
        let (extensions, v) = read_tls_vec_as_vector_with_selector(
            v,
            2,
            &ExtensionSelector::ClientHello,
        )?;
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

impl_to_tls! {
    ClientHello(self) {
        [
            self.legacy_version.to_tls_vec(),
            self.random.to_vec(),
            write_tls_vec_as_vector(&self.legacy_session_id, 1),
            write_tls_vec_as_vector(&self.cipher_suites, 2),
            write_tls_vec_as_vector(&self.legacy_compression_methods, 1),
            write_tls_vec_as_vector(&self.extensions, 2),
        ]
        .concat()
    }
}
