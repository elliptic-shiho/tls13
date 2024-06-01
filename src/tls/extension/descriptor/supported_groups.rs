use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, write_tls_vec_as_vector, FromTlsVec,
    ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(non_camel_case_types)]
pub enum NamedGroup {
    secp256r1,
    secp384r1,
    secp521r1,
    x25519,
    x448,
    ffdhe2048,
    ffdhe3072,
    ffdhe4096,
    ffdhe6144,
    ffdhe8192,
    ffdhe_private_use(u16),
    ecdhe_private_use(u16),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SupportedGroupsDescriptor {
    pub named_group_list: Vec<NamedGroup>,
}

impl_to_tls! {
    SupportedGroupsDescriptor(self) {
        write_tls_vec_as_vector(&self.named_group_list, 2)
    }

    NamedGroup(self) {
        match self {
            Self::secp256r1 => 0x0017,
            Self::secp384r1 => 0x0018,
            Self::secp521r1 => 0x0019,
            Self::x25519 => 0x001d,
            Self::x448 => 0x001e,
            Self::ffdhe2048 => 0x100,
            Self::ffdhe3072 => 0x101,
            Self::ffdhe4096 => 0x102,
            Self::ffdhe6144 => 0x103,
            Self::ffdhe8192 => 0x104,
            Self::ffdhe_private_use(x) => *x,
            Self::ecdhe_private_use(x) => *x
        }.to_tls_vec()
    }
}

impl_from_tls! {
    SupportedGroupsDescriptor(v) {
        let (named_group_list, v) = read_tls_vec_as_vector(v, 2)?;
        Ok((Self { named_group_list }, v))
    }

    NamedGroup(v) {
        let (x, v) = u16::from_tls_vec(v)?;
        Ok((if (0x01fcu16..0x01ffu16).contains(&x) {
            Self::ffdhe_private_use(x)
        } else if (0xfe00u16..0xfeffu16).contains(&x) {
            Self::ecdhe_private_use(x)
        } else {
            match x {
                0x0017u16 => Self::secp256r1,
                0x0018 => Self::secp384r1,
                0x0019 => Self::secp521r1,
                0x001d => Self::x25519,
                0x001e => Self::x448,
                0x100 => Self::ffdhe2048,
                0x101 => Self::ffdhe3072,
                0x102 => Self::ffdhe4096,
                0x103 => Self::ffdhe6144,
                0x104 => Self::ffdhe8192,
                _ => return Err(crate::Error::TlsError(format!("Invalid NamedGroup Specified: {:04x}", x)))
            }
        }, v))
    }
}
