use crate::tls::SignatureScheme;
use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, write_tls_vec_as_vector, FromTlsVec,
    ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignatureAlgorithmsDescriptor {
    pub supported_signature_algorithms: Vec<SignatureScheme>,
}

impl_to_tls! {
    SignatureAlgorithmsDescriptor(self) {
        write_tls_vec_as_vector(&self.supported_signature_algorithms, 2)
    }
}

impl_from_tls! {
    SignatureAlgorithmsDescriptor(v) {
        let (supported_signature_algorithms, v) = read_tls_vec_as_vector(v, 2)?;
        Ok((
            SignatureAlgorithmsDescriptor {
                supported_signature_algorithms,
            },
            v,
        ))
    }
}
