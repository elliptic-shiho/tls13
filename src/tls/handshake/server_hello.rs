use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, read_tls_vec_as_vector_with_selector,
    write_tls_vec_as_vector, CipherSuite, Extension, FromTlsVec, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct ServerHello {
    legacy_version: u16,
    pub random: Vec<u8>,
    legacy_session_id_echo: Vec<u8>,
    pub cipher_suite: CipherSuite,
    legacy_compression_method: u8,
    extensions: Vec<Extension>,
}

impl_from_tls! {
    ServerHello(v) {
        let (legacy_version, v) = u16::from_tls_vec(v)?;
        let (random, v) = (v[..32].to_vec(), &v[32..]);
        let (legacy_session_id_echo, v) = read_tls_vec_as_vector(v, 1)?;
        let (cipher_suite, v) = CipherSuite::from_tls_vec(v)?;
        let (legacy_compression_method, v) = u8::from_tls_vec(v)?;
        let (extensions, v) = read_tls_vec_as_vector_with_selector(
            v,
            2,
            &crate::tls::handshake::ExtensionSelector::ServerHello,
        )?;

        Ok((
            Self {
                legacy_version,
                random,
                legacy_session_id_echo,
                cipher_suite,
                legacy_compression_method,
                extensions
            },
            v,
        ))
    }
}

impl_to_tls! {
    ServerHello(self) {
        [
            self.legacy_version.to_tls_vec(),
            self.random.to_vec(),
            write_tls_vec_as_vector(&self.legacy_session_id_echo, 1),
            self.cipher_suite.to_tls_vec(),
            self.legacy_compression_method.to_tls_vec(),
            write_tls_vec_as_vector(&self.extensions, 2)
        ].concat()
    }
}
