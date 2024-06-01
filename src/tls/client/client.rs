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
use hex_literal::hex;
use rand::prelude::*;
use std::io::prelude::*;
use std::net::TcpStream;

pub struct Client<T: CryptoRng + RngCore> {
    conn: TcpStream,
    host: String,
    keyman: TlsKeyManager<T>,
    sequence_number_client: u64,
    sequence_number_server: u64,
    state: ClientState,
    psk: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
enum ClientState {
    Start,
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificateRequest,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
}

impl ClientState {
    pub fn can_encrypt(&self) -> bool {
        !matches!(self, Self::Start | Self::WaitServerHello)
    }
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
            state: ClientState::Start,
            psk: None,
        })
    }

    pub fn set_psk(&mut self, psk: &[u8]) {
        self.keyman.set_psk(psk.to_vec());
        self.psk = Some(psk.to_vec())
    }

    pub fn handshake(&mut self) -> Result<Vec<u8>> {
        let ch = self.create_client_hello();
        let hs = Handshake::ClientHello(ch);
        self.keyman.handle_handshake_record_client(hs.clone());
        self.state = self.handshake_state_transition(hs.clone())?;
        let seq = self.incr_sequence_number_client();
        self.send_record(TlsRecord::Handshake(hs, seq))?;

        for record in self.recv()? {
            self.handle_record_from_server(record, true)?;
        }

        assert_eq!(self.state, ClientState::Connected);

        let mut ret = vec![];
        for record in self.recv()? {
            ret.push(self.handle_record_from_server(record, true)?);
        }

        Ok(ret.concat())
    }

    pub fn send_tls_message(&mut self, v: &[u8]) -> Result<()> {
        let seq = self.incr_sequence_number_client();
        self.send_record(TlsRecord::ApplicationData(v.to_vec(), seq))
    }

    pub fn recv_tls_message(&mut self) -> Result<Vec<u8>> {
        let mut res = vec![];
        for record in self.recv()? {
            if let TlsRecord::ApplicationData(data, _) = record {
                res.push(data);
            }
        }

        Ok(res.concat())
    }

    fn send_record(&mut self, record: TlsRecord) -> Result<()> {
        let record = if self.state.can_encrypt() {
            self.keyman.encrypt_record(&record)
        } else {
            record
        };
        self.conn.write_all(&record.to_tls_vec())?;
        Ok(())
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

    // [RFC8446] Section A.1 "Client"
    fn handshake_state_transition(&mut self, hs: Handshake) -> Result<ClientState> {
        Ok(match (&self.state, hs) {
            (&ClientState::Start, Handshake::ClientHello(ch)) => {
                let mut found_early_data = false;
                let mut found_psk = false;
                for extension in &ch.extensions {
                    found_early_data |= matches!(extension, Extension::EarlyData);
                    found_psk |= matches!(extension, Extension::PreSharedKey);
                }
                if found_early_data && found_psk {
                    ClientState::WaitFinished
                } else {
                    ClientState::WaitServerHello
                }
            }
            (&ClientState::WaitServerHello, Handshake::ServerHello(sh)) => {
                // [RFC8446] Section 4.1.3 "Server Hello"
                const SPECIAL_RANDOM: [u8; 32] =
                    hex!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
                const DOWNGRADE_RANDOM: [u8; 8] = hex!("444F574E47524400");
                if sh.random == SPECIAL_RANDOM {
                    // HelloRetryRequest
                    ClientState::Start
                } else if sh.random[24..] == DOWNGRADE_RANDOM {
                    // Downgrade to TLS 1.2 is disabled
                    let _ = self.send_record(TlsRecord::Alert(
                        Alert {
                            level: AlertLevel::Fatal,
                            description: AlertDescription::IllegalParameter,
                        },
                        0,
                    ));
                    panic!();
                } else {
                    ClientState::WaitEncryptedExtensions
                }
            }
            (&ClientState::WaitEncryptedExtensions, Handshake::EncryptedExtensions(_)) => {
                if self.psk.is_some() {
                    ClientState::WaitFinished
                } else {
                    ClientState::WaitCertificateRequest
                }
            }
            (&ClientState::WaitCertificateRequest, Handshake::CertificateRequest) => {
                ClientState::WaitCertificate
            }
            (&ClientState::WaitCertificateRequest, Handshake::Certificate(_)) => {
                ClientState::WaitCertificateVerify
            }
            (&ClientState::WaitCertificate, Handshake::Certificate(_)) => {
                ClientState::WaitCertificateVerify
            }
            (&ClientState::WaitCertificateVerify, Handshake::CertificateVerify(_)) => {
                ClientState::WaitFinished
            }
            (&ClientState::WaitFinished, Handshake::Finished(_)) => {
                let seq = self.incr_sequence_number_client();
                let hs = Handshake::Finished(Finished {
                    verify_data: self.keyman.get_verify_data(),
                });
                self.keyman.handle_handshake_record_client(hs.clone());
                self.send_record(TlsRecord::Handshake(hs.clone(), seq))?;

                // Reset sequence number to encrypt / decrypt ApplicationData
                self.sequence_number_server = 0;
                self.sequence_number_client = 0;

                // Change secret to ApplicationData's one
                self.keyman.finish_handshake();

                ClientState::Connected
            }
            (&ClientState::Connected, _) => {
                // ignore
                ClientState::Connected
            }
            (state, hs) => {
                dbg!(state);
                dbg!(hs);
                panic!("Invalid State");
            }
        })
    }

    fn create_client_hello(&mut self) -> ClientHello {
        ClientHello::new(
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
        )
    }

    fn incr_sequence_number_client(&mut self) -> u64 {
        let ret = self.sequence_number_client;
        if self.state.can_encrypt() {
            self.sequence_number_client += 1;
        }
        ret
    }

    fn handle_handshake_from_server(&mut self, hs: Handshake) -> Result<()> {
        self.keyman.handle_handshake_record(hs.clone());
        self.state = self.handshake_state_transition(hs.clone())?;

        Ok(())
    }

    fn handle_record_from_server(&mut self, record: TlsRecord, encrypted: bool) -> Result<Vec<u8>> {
        let mut ret = vec![];
        match &record {
            TlsRecord::Handshake(hs, _) => self.handle_handshake_from_server(hs.clone())?,
            TlsRecord::ChangeCipherSpec(_, _) => {}
            TlsRecord::ApplicationData(data, _) => {
                if encrypted {
                    assert!(self.state.can_encrypt());
                    let decrypted = self.keyman.decrypt_record(&record)?;
                    self.handle_record_from_server(decrypted, false)?;
                } else {
                    ret.push(data.clone())
                }
            }
            TlsRecord::Alert(al, _) => {
                println!(
                    "[-] Alert: (Level: {:?}, Description: {:?})",
                    al.level, al.description
                );
                panic!();
            }
        }

        Ok(ret.concat())
    }
}

impl<T: CryptoRng + RngCore> Drop for Client<T> {
    fn drop(&mut self) {
        let _ = self.send_record(TlsRecord::Alert(
            Alert {
                level: AlertLevel::Fatal,
                description: AlertDescription::CloseNotify,
            },
            self.sequence_number_client,
        ));
    }
}
