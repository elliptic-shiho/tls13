use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, write_tls_vec_as_vector, FromTlsVec,
    ToTlsVec,
};
use crate::Result;
use num_derive::{FromPrimitive, ToPrimitive};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PskKeyExchangeModesDescriptor {
    pub ke_modes: Vec<PskKeyExchangeMode>,
}

#[repr(u8)]
#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq, Clone)]
pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}

impl_from_tls! {
    PskKeyExchangeMode(v) {
        let (x, v) = u8::from_tls_vec(v)?;
        Ok((
            num_traits::FromPrimitive::from_u8(x)
                .expect("Invalid value specified at PskKeyExchangeMode::from_tls_vec"),
            v,
        ))
    }

    PskKeyExchangeModesDescriptor(v) {
        let (ke_modes, v) = read_tls_vec_as_vector(v, 1)?;
        Ok((Self {
            ke_modes
        }, v))
    }
}

impl_to_tls! {
    PskKeyExchangeMode(self) {
        num_traits::ToPrimitive::to_u8(self).unwrap().to_tls_vec()
    }

    PskKeyExchangeModesDescriptor(self) {
        write_tls_vec_as_vector(&self.ke_modes, 1)
    }
}
