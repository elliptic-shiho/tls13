use crate::tls::client::TlsKeyManager;
use crate::tls::extension::descriptor::{
    KeyShareDescriptor, KeyShareEntry, NamedGroup, ServerName, ServerNameDescriptor,
    SignatureAlgorithmsDescriptor, SignatureScheme, SupportedGroupsDescriptor,
    SupportedVersionsDescriptor,
};
use crate::tls::handshake::{ClientHello, Finished, Handshake};
use crate::tls::protocol::{Alert, AlertDescription, AlertLevel, TlsRecord};
use crate::tls::{CipherSuite, Extension, ToTlsVec};
use crate::Result;
use rand::prelude::*;
use std::io::prelude::*;
use std::net::TcpStream;

pub struct Client<T: CryptoRng + RngCore> {
    conn: TcpStream,
    host: String,
    keyman: TlsKeyManager<T>,
    sequence_number_client: u64,
    sequence_number_server: u64,
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
            sequence_number_client: 0,
            sequence_number_server: 0,
        })
    }

    fn send_record(&mut self, record: TlsRecord) -> Result<()> {
        self.conn.write_all(&record.to_tls_vec())?;
        Ok(())
    }

    fn send_handshake(&mut self, hs: Handshake) -> Result<()> {
        self.keyman.handle_handshake_record_client(hs.clone());
        self.send_record(TlsRecord::Handshake(hs, 0))
    }

    fn send_handshake_encrypted(&mut self, hs: Handshake) -> Result<()> {
        self.keyman.handle_handshake_record_client(hs.clone());
        let record = TlsRecord::Handshake(hs, self.sequence_number_client);
        self.sequence_number_client += 1;
        let encrypted_record = self.keyman.encrypt_record(&record);
        self.send_record(encrypted_record)
    }

    fn send_record_encrypted(&mut self, record: TlsRecord) -> Result<()> {
        let encrypted = self.keyman.encrypt_record(&record);
        self.send_record(encrypted)
    }

    fn recv_raw(&mut self) -> Result<Vec<u8>> {
        let mut res = vec![];
        const N: usize = 256;
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
            let (rec, t) = TlsRecord::parse(&v, self.sequence_number_server)?;
            if matches!(rec, TlsRecord::ApplicationData(_, _)) {
                self.sequence_number_server += 1;
            }
            let t2 = rec.to_tls_vec();
            if t2 != v2[..t2.len()] {
                dbg!(&t2);
                dbg!(&v2[..t2.len()]);
                dbg!(&rec);
                panic!();
            }
            records.push(rec);
            v = t.to_vec();
        }
        Ok(records)
    }

    pub fn handshake(&mut self) -> Result<Vec<TlsRecord>> {
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

        let mut inner_plaintext = vec![];

        for record in self.recv()? {
            match &record {
                TlsRecord::Handshake(hs, _) => {
                    self.keyman.handle_handshake_record(hs.clone());
                }
                TlsRecord::ChangeCipherSpec(_, _) => {
                    // println!("[+] ChangeCipherSpec");
                }
                TlsRecord::ApplicationData(_, _) => {
                    inner_plaintext.push(self.keyman.decrypt_record(&record)?);
                }
                x => {
                    dbg!(&x);
                }
            }
        }

        for record in &inner_plaintext {
            match &record {
                TlsRecord::Handshake(hs, _) => {
                    self.keyman.handle_handshake_record(hs.clone());

                    if matches!(hs, Handshake::Finished(_)) {
                        self.send_handshake_encrypted(Handshake::Finished(Finished {
                            verify_data: self.keyman.get_verify_data(),
                        }))?;
                        break;
                    }
                }
                x => {
                    dbg!(&x);
                }
            }
        }

        self.sequence_number_server = 0;
        self.sequence_number_client = 0;
        self.keyman.finish_handshake();

        for record in self.recv()? {
            match &record {
                TlsRecord::ApplicationData(_, _) => {
                    self.keyman.decrypt_record(&record)?;
                }
                x => {
                    dbg!(&x);
                }
            }
        }

        Ok(vec![])
    }

    pub fn send_tls_message(&mut self, v: &[u8]) -> Result<()> {
        let record = TlsRecord::ApplicationData(v.to_vec(), self.sequence_number_client);
        self.sequence_number_client += 1;
        let encrypted = self.keyman.encrypt_record(&record);
        self.send_record(encrypted)
    }

    pub fn recv_tls_message(&mut self) -> Result<Vec<u8>> {
        let mut res = vec![];
        let mut records = vec![];
        for record in &self.recv()? {
            if let TlsRecord::ApplicationData(_, _) = record {
                records.push(self.keyman.decrypt_record(record)?);
            }
        }

        for record in records {
            if let TlsRecord::ApplicationData(data, _) = record {
                res.push(data.clone());
            }
        }

        Ok(res.concat())
    }
}

impl<T: CryptoRng + RngCore> Drop for Client<T> {
    fn drop(&mut self) {
        let _ = self.send_record_encrypted(TlsRecord::Alert(
            Alert {
                level: AlertLevel::Fatal,
                description: AlertDescription::CloseNotify,
            },
            self.sequence_number_client,
        ));
    }
}
