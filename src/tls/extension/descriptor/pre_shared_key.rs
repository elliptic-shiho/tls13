use crate::tls::{
    impl_from_tls, impl_from_tls_with_selector, impl_to_tls, read_tls_vec_as_vector,
    write_tls_vec_as_vector, ExtensionSelector, FromTlsVec, FromTlsVecWithSelector, ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PreSharedKeyDescriptor {
    ClientHello(OfferedPsks),
    ServerHello(u16),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OfferedPsks {
    pub identities: Vec<PskIdentity>,
    pub binders: Vec<Vec<u8>>,
}

impl_from_tls! {
    PskIdentity(v) {
        let (identity, v) = read_tls_vec_as_vector(v, 2)?;
        let (obfuscated_ticket_age, v) = u32::from_tls_vec(v)?;
        Ok((Self {
            identity,
            obfuscated_ticket_age
        }, v))
    }

    OfferedPsks(v) {
        let (identities, v) = read_tls_vec_as_vector(v, 2)?;
        let (len, v) = u16::from_tls_vec(v)?;
        let mut v = v;
        let mut read_len = 0u16;
        let mut binders = vec![];
        while read_len < len {
            let (entry, t) = read_tls_vec_as_vector(v, 1)?;
            binders.push(entry);
            read_len += (v.len() - t.len()) as u16;
            v = t;
        }
        Ok((Self {
            identities,
            binders
        }, v))
    }
}

impl_to_tls! {
    PskIdentity(self) {
        [
            write_tls_vec_as_vector(&self.identity, 2),
            self.obfuscated_ticket_age.to_tls_vec()
        ].concat()
    }

    OfferedPsks(self) {
        let binders_vec = self
            .binders
            .iter()
            .map(|entry| write_tls_vec_as_vector(entry, 1))
            .fold(vec![], |x, y| [x, y].concat());
        [
            write_tls_vec_as_vector(&self.identities, 2),
            write_tls_vec_as_vector(&binders_vec, 2),
        ]
        .concat()
    }

    PreSharedKeyDescriptor(self) {
        match self {
            Self::ClientHello(op) => op.to_tls_vec(),
            Self::ServerHello(si) => si.to_tls_vec()
        }
    }
}

impl_from_tls_with_selector! {
    PreSharedKeyDescriptor<ExtensionSelector>(v, selector) {
        match selector {
            ExtensionSelector::ClientHello => {
                let (op, v) = OfferedPsks::from_tls_vec(v)?;
                Ok((Self::ClientHello(op), v))
            }
            ExtensionSelector::ServerHello => {
                let (si, v) = u16::from_tls_vec(v)?;
                Ok((Self::ServerHello(si), v))
            }
            _ => unreachable!()
        }
    }
}
