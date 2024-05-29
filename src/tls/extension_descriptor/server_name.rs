use crate::tls::{impl_from_tls, impl_to_tls, FromByteVec, ToByteVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct ServerNameDescriptor {
    pub server_names: Vec<ServerName>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServerName {
    HostName(String),
}

impl_to_tls! {
    ServerNameDescriptor(self) {
        self.server_names.to_tls_vec()
    }

    ServerName(self) {
        match self {
            Self::HostName(name) => [vec![0], name.to_tls_vec()].concat(),
        }
    }
}

impl_from_tls! {
    ServerNameDescriptor(v) {
        let (server_names, v): (Vec<ServerName>, &[u8]) = Vec::from_tls_vec(v)?;
        Ok((Self { server_names }, v))
    }

    ServerName(v) {
        let (name_type, v) = u8::from_tls_vec(v)?;
        if name_type == 0 {
            // HostName
            let (server_name, v) = String::from_tls_vec(v)?;
            Ok((Self::HostName(server_name), v))
        } else {
            // NameType is only contained "HostName" at RFC6066
            unreachable!();
        }
    }
}
