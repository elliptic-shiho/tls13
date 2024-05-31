use crate::tls::handshake::ExtensionSelector;
use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, read_tls_vec_as_vector_with_selector,
    write_tls_vec_as_vector, Extension, FromTlsVec, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NewSessionTicket {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: Vec<u8>,
    ticket: Vec<u8>,
    extensions: Vec<Extension>,
}

impl_from_tls! {
    NewSessionTicket(v) {
        let (ticket_lifetime, v) = u32::from_tls_vec(v)?;
        let (ticket_age_add, v) = u32::from_tls_vec(v)?;
        let (ticket_nonce, v) = read_tls_vec_as_vector(v, 1)?;
        let (ticket, v) = read_tls_vec_as_vector(v, 2)?;
        let (extensions, v) = read_tls_vec_as_vector_with_selector(v, 2, &ExtensionSelector::NewSessionTicket)?;
        Ok((Self {
            ticket_lifetime,
            ticket_age_add,
            ticket_nonce,
            ticket,
            extensions
        }, v))
    }
}

impl_to_tls! {
    NewSessionTicket(self) {
        [
            self.ticket_lifetime.to_tls_vec(),
            self.ticket_age_add.to_tls_vec(),
            write_tls_vec_as_vector(&self.ticket_nonce, 1),
            write_tls_vec_as_vector(&self.ticket, 2),
            write_tls_vec_as_vector(&self.extensions, 2),
        ].concat()
    }
}
