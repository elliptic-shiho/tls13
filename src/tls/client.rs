use crate::Result;
use std::io::prelude::*;
use std::net::TcpStream;

pub struct Client {
    conn: TcpStream,
}

impl Client {
    pub fn open(host: &str, port: i32) -> Result<Self> {
        Ok(Self {
            conn: TcpStream::connect(format!("{}:{}", host, port))?,
        })
    }
}
