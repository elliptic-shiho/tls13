use crate::tls::{FromByteVec, ToByteVec};
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct ServerNameDescriptor {
    pub server_names: Vec<ServerName>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServerName {
    HostName(String),
}

impl ToByteVec for ServerNameDescriptor {
    fn to_tls_vec(&self) -> Vec<u8> {
        self.server_names.to_tls_vec()
    }
}

impl FromByteVec for ServerNameDescriptor {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
        let (server_names, v): (Vec<ServerName>, &[u8]) = Vec::from_tls_vec(v)?;
        Ok((Self { server_names }, v))
    }
}

impl ToByteVec for ServerName {
    fn to_tls_vec(&self) -> Vec<u8> {
        match self {
            Self::HostName(name) => [vec![0], name.to_tls_vec()].concat(),
        }
    }
}

impl FromByteVec for ServerName {
    fn from_tls_vec(v: &[u8]) -> Result<(Self, &[u8])> {
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
