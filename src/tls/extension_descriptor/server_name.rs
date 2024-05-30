use crate::tls::{
    impl_from_tls, impl_to_tls, read_tls_vec_as_vector, write_tls_vec_as_vector, FromTlsVec,
    ToTlsVec,
};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ServerNameDescriptor {
    pub server_names: Vec<ServerName>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ServerName {
    HostName(String),
}

impl_to_tls! {
    ServerNameDescriptor(self) {
        write_tls_vec_as_vector(&self.server_names, 2)
    }

    ServerName(self) {
        match self {
            Self::HostName(name) => {
                let v = name.as_bytes();
                [vec![0], (v.len() as u16).to_tls_vec(), v.to_vec()].concat()
            },
        }
    }
}

impl_from_tls! {
    ServerNameDescriptor(v) {
        let (server_names, v): (Vec<ServerName>, &[u8]) = read_tls_vec_as_vector(v, 2)?;
        Ok((Self { server_names }, v))
    }

    ServerName(v) {
        let (name_type, v) = u8::from_tls_vec(v)?;
        if name_type == 0 {
            // HostName
            let (server_name, v) = read_tls_vec_as_vector(v, 2)?;
            Ok((Self::HostName(String::from_utf8(server_name).unwrap()), v))
        } else {
            // NameType is only contained "HostName" at RFC6066
            unreachable!();
        }
    }
}
