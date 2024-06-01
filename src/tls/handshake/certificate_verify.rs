use crate::tls::extension::descriptor::SignatureScheme;
use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, write_tls_vec_as_vector, FromTlsVec,
    ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CertificateVerify {
    pub algorithm: SignatureScheme,
    pub signature: Vec<u8>,
}

impl_from_tls! {
    CertificateVerify(v) {
        let (algorithm, v) = SignatureScheme::from_tls_vec(v)?;
        let (signature, v) = read_tls_vec_as_vector(v, 2)?;
        Ok((Self {
            algorithm,
            signature
        }, v))
    }
}

impl_to_tls! {
    CertificateVerify(self) {
        [
            self.algorithm.to_tls_vec(),
            write_tls_vec_as_vector(&self.signature, 2)
        ].concat()
    }
}
