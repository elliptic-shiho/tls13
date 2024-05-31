use crate::tls::{impl_from_tls, impl_to_tls, FromTlsVec, ToTlsVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl_from_tls! {
    Finished(v) {
        Ok((Self {
            verify_data: v.to_vec(),
        }, &[]))
    }
}

impl_to_tls! {
    Finished(self) {
        self.verify_data.to_vec()
    }
}
