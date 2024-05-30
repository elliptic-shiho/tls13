use crate::tls::handshake::ExtensionSelector;
use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, read_tls_vec_as_vector_with_selector,
    write_tls_vec_as_vector, Extension, FromTlsVec, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Certificate {
    certificate_request_context: Vec<u8>,
    certificate_list: Vec<CertificateEntry>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CertificateEntry {
    cert_data: Vec<u8>,
    extensions: Vec<Extension>,
}

impl_from_tls! {
    CertificateEntry(v) {
        let (cert_data, v) = read_tls_vec_as_vector(v, 3)?;
        let (extensions, v) = read_tls_vec_as_vector_with_selector(v, 2, &ExtensionSelector::Certificate)?;
        Ok((Self {
            cert_data,
            extensions
        }, v))
    }

    Certificate(v) {
        let (certificate_request_context, v) = read_tls_vec_as_vector(v, 1)?;
        let (certificate_list, v) = read_tls_vec_as_vector(v, 3)?;
        Ok((Self {
            certificate_request_context,
            certificate_list
        }, v))
    }
}

impl_to_tls! {
    CertificateEntry(self) {
        [
            write_tls_vec_as_vector(&self.cert_data, 3),
            write_tls_vec_as_vector(&self.extensions, 2),
        ].concat()
    }

    Certificate(self) {
        [
            write_tls_vec_as_vector(&self.certificate_request_context, 1),
            write_tls_vec_as_vector(&self.certificate_list, 3),
        ].concat()
    }
}
