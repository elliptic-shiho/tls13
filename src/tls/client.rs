use crate::tls::{FromTlsVec, Handshake, TlsRecord, ToTlsVec};
use crate::Result;
use std::io::prelude::*;
use std::net::TcpStream;

pub struct Client {
    conn: TcpStream,
}

impl Client {
    pub fn open(host: &str, port: i32) -> Result<Self> {
        let conn = TcpStream::connect(format!("{}:{}", host, port))?;
        Ok(Self { conn })
    }
    pub fn send_record(&mut self, record: TlsRecord) -> Result<()> {
        self.conn.write_all(&record.to_tls_vec())?;
        Ok(())
    }

    pub fn send_handshake(&mut self, hs: Handshake) -> Result<()> {
        self.send_record(TlsRecord::Handshake(hs))
    }

    fn recv_raw(&mut self) -> Result<Vec<u8>> {
        let mut res = vec![];
        const N: usize = 8192;
        let mut v: [u8; N] = [0; N];

        loop {
            let len = self.conn.read(&mut v)?;
            res.extend_from_slice(&v[..len]);
            if len < N {
                break;
            }
        }
        Ok(res)
    }

    pub fn recv(&mut self) -> Result<Vec<TlsRecord>> {
        let mut v = self.recv_raw()?;

        let mut records = vec![];
        while !v.is_empty() {
            let (rec, t) = TlsRecord::from_tls_vec(&v)?;
            records.push(rec);
            v = t.to_vec();
        }
        Ok(records)
    }
}
