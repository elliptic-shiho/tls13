use crate::tls::crypto::TlsKeyManager;
use crate::tls::{CipherSuite, ClientHello, Extension, Handshake, TlsRecord, ToTlsVec};
use crate::Result;
use rand::prelude::*;
use std::io::prelude::*;
use std::net::TcpStream;

pub struct Client<T: CryptoRng + RngCore> {
    conn: TcpStream,
    host: String,
    keyman: TlsKeyManager<T>,
    sequence_number: u64,
}

impl<T: CryptoRng + RngCore> Client<T> {
    pub fn open(host: &str, port: i32, rng: T) -> Result<Self>
    where
        T: CryptoRng + RngCore + Clone,
    {
        let conn = TcpStream::connect(format!("{}:{}", host, port))?;
        let keyman = TlsKeyManager::new(Box::new(rng));
        Ok(Self {
            conn,
            host: host.to_string(),
            keyman,
            sequence_number: 0,
        })
    }

    fn send_record(&mut self, record: TlsRecord) -> Result<()> {
        self.conn.write_all(&record.to_tls_vec())?;
        Ok(())
    }

    fn send_handshake(&mut self, hs: Handshake) -> Result<()> {
        self.keyman.handle_handshake_record(hs.clone());
        let ret = self.send_record(TlsRecord::Handshake(hs, self.sequence_number));
        self.sequence_number += 1;
        ret
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

    fn recv(&mut self) -> Result<Vec<TlsRecord>> {
        let mut v = self.recv_raw()?;

        let mut records = vec![];
        while !v.is_empty() {
            let v2 = v.clone();
            let (rec, t) = TlsRecord::parse(&v, self.sequence_number)?;
            let t2 = rec.to_tls_vec();
            if t2 != v2[..t2.len()] {
                dbg!(&t2);
                dbg!(&v2[..t2.len()]);
                dbg!(&rec);
                panic!();
            }
            records.push(rec);
            self.sequence_number += 1;
            v = t.to_vec();
        }
        Ok(records)
    }

    pub fn handshake(&mut self) -> Result<()> {
        use crate::tls::extension_descriptor::*;
        let ch = ClientHello::new(
            self.keyman.gen_client_random(),
            vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            vec![
                Extension::ServerName(ServerNameDescriptor {
                    server_names: vec![ServerName::HostName(self.host.clone())],
                }),
                Extension::SignatureAlgorithms(SignatureAlgorithmsDescriptor {
                    supported_signature_algorithms: vec![SignatureScheme::ecdsa_secp256r1_sha256],
                }),
                Extension::SupportedVersions(SupportedVersionsDescriptor::ClientHello(vec![
                    0x0304,
                ])),
                Extension::SupportedGroups(SupportedGroupsDescriptor {
                    named_group_list: vec![NamedGroup::secp256r1],
                }),
                Extension::KeyShare(KeyShareDescriptor::ClientHello(vec![KeyShareEntry {
                    group: NamedGroup::secp256r1,
                    key_exchange: self.keyman.gen_client_pubkey().to_bytes().to_vec(),
                }])),
            ],
        );
        self.send_handshake(Handshake::ClientHello(ch))?;

        for record in self.recv()? {
            match &record {
                TlsRecord::Handshake(hs, _) => {
                    self.keyman.handle_handshake_record(hs.clone());
                }
                TlsRecord::ChangeCipherSpec(_, _) => {
                    println!("[+] ChangeCipherSpec");
                }
                TlsRecord::ApplicationData(encrypted, _) => {
                    let additional_data = record.get_additional_data();
                    let nonce = record.get_nonce();
                    dbg!(self
                        .keyman
                        .decrypt_handshake(encrypted, &nonce, &additional_data));
                }
                x => {
                    dbg!(&x);
                }
            }
        }

        Ok(())
    }
}
