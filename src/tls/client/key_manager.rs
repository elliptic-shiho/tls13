use crate::tls::extension::descriptor::{KeyShareDescriptor, PreSharedKeyDescriptor};
use crate::tls::handshake::Certificate;
use crate::tls::protocol::Handshake;
use crate::tls::{CipherSuite, Extension, TlsRecord, ToTlsVec};
use crate::Result;
use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::{EncodedPoint, PublicKey};
use rand::prelude::*;
use x509_parser::prelude::*;

pub struct TlsKeyManager<T: CryptoRng + RngCore> {
    rng: Box<T>,
    cipher_suite: Option<CipherSuite>,
    client_ecdh_key: Option<EphemeralSecret>,
    shared_secret: Option<SharedSecret>,
    current_context: Vec<u8>,
    psk: Option<Vec<u8>>,
    early_secret: Option<Vec<u8>>,
    handshake_secret: Option<Vec<u8>>,
    cert_type: CertificateType,
    server_cert: Option<Certificate>,
    client_traffic_secret: Vec<u8>,
    server_traffic_secret: Vec<u8>,
    context: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CertificateType {
    X509,
    // RawPublicKey,
}

impl<T: CryptoRng + RngCore> TlsKeyManager<T> {
    pub fn new(rng: Box<T>) -> Self {
        Self {
            rng,
            cipher_suite: None,
            client_ecdh_key: None,
            shared_secret: None,
            current_context: vec![],
            psk: None,
            early_secret: None,
            handshake_secret: None,
            cert_type: CertificateType::X509,
            server_cert: None,
            client_traffic_secret: vec![],
            server_traffic_secret: vec![],
            context: vec![],
        }
    }

    pub fn gen_random_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut rand_value = vec![0u8; n];
        self.rng.fill_bytes(&mut rand_value);
        rand_value
    }

    pub fn gen_client_pubkey(&mut self) -> EncodedPoint {
        self.client_ecdh_key = Some(EphemeralSecret::random(&mut self.rng));
        EncodedPoint::from(self.client_ecdh_key.as_ref().unwrap().public_key())
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suite = Some(cipher_suite);
        self.update_early_secret();
    }

    pub fn set_server_pubkey(&mut self, server_pubkey: Vec<u8>) {
        let server_pubkey = PublicKey::from_sec1_bytes(&server_pubkey).unwrap();
        if let Some(client_key) = self.client_ecdh_key.as_ref() {
            let shared_secret = client_key.diffie_hellman(&server_pubkey);
            self.shared_secret = Some(shared_secret);
        } else {
            panic!();
        }
    }

    pub fn set_psk(&mut self, psk: Vec<u8>) {
        self.psk = Some(psk);
        if self.cipher_suite.is_some() {
            self.update_early_secret();
        }
    }

    pub fn is_set_psk(&self) -> bool {
        self.psk.is_some()
    }

    pub fn handle_handshake_record_client(&mut self, hs: Handshake) {
        if matches!(hs, Handshake::Finished(_)) {
            self.update_application_secret();
        }
        self.current_context = [self.current_context.clone(), hs.to_tls_vec()].concat();
    }

    pub fn handle_handshake_record(&mut self, hs: Handshake) {
        self.current_context = [self.current_context.clone(), hs.to_tls_vec()].concat();
        match &hs {
            Handshake::ServerHello(sh) => {
                self.set_cipher_suite(sh.cipher_suite.clone());
                for ext in &sh.extensions {
                    match &ext {
                        Extension::KeyShare(desc) => {
                            if let KeyShareDescriptor::ServerHello(entry) = desc {
                                self.set_server_pubkey(entry.key_exchange.clone());
                            } else {
                                dbg!(&sh);
                                panic!();
                            }
                        }
                        Extension::PreSharedKey(PreSharedKeyDescriptor::ServerHello(
                            identity_index,
                        )) => {
                            println!("[+] Server has been selected the PSK[{}]", identity_index);
                        }
                        _ => {}
                    }
                }
                self.update_handshake_secret();
            }
            Handshake::EncryptedExtensions(ee) => {
                if !ee.is_empty() {
                    dbg!(ee);
                }
                self.context.clone_from(&self.current_context);
            }
            Handshake::Certificate(cert) => {
                match self.cert_type {
                    CertificateType::X509 => {
                        self.server_cert = Some(cert.clone());
                    }
                }
                self.context.clone_from(&self.current_context);
            }
            Handshake::CertificateVerify(cert_verify) => {
                // [RFC8446] Section 4.4.3 "CertificateVerify"
                let server_cert = self.server_cert.as_ref().unwrap();
                let transcript_hash = self.get_ciphersuite().hash(self.context.clone());
                let raw = [
                    vec![0x20; 64],
                    b"TLS 1.3, server CertificateVerify".to_vec(),
                    vec![0],
                    transcript_hash,
                ]
                .concat();

                let raw_cert = server_cert
                    .certificate_list
                    .first()
                    .as_ref()
                    .unwrap()
                    .cert_data
                    .clone();

                let x509_cert = X509Certificate::from_der(&raw_cert).unwrap().1;
                println!("[+] Issuer: {}", x509_cert.issuer);
                println!(
                    "[+] Signature Algorithm: {}",
                    x509_cert.signature_algorithm.algorithm
                );
                match x509_cert.public_key().parsed().unwrap() {
                    x509_parser::public_key::PublicKey::EC(point) => {
                        if !cert_verify
                            .algorithm
                            .verify(&raw, &cert_verify.signature, point.data())
                        {
                            panic!("Failed to verify the server certificate");
                        }
                    }
                    _ => todo!(),
                }
                self.context.clone_from(&self.current_context);
            }
            Handshake::Finished(fin) => {
                // [RFC8446] Section 4.4.4 "Finished"
                if self.compute_finished(&self.server_traffic_secret, &self.context)
                    != fin.verify_data
                {
                    panic!("Failed to verify the server finished hmac");
                }

                self.context.clone_from(&self.current_context);
            }
            Handshake::NewSessionTicket(_) => {
                // ignore
            }
            x => {
                dbg!(&x);
            }
        }
    }

    pub fn encrypt_record(&mut self, record: &TlsRecord) -> TlsRecord {
        let inner_plaintext = record.unparse_inner_plaintext();
        let aad = [
            vec![23, 3, 3],
            ((inner_plaintext.len() + self.get_ciphersuite().tag_length()) as u16).to_tls_vec(),
        ]
        .concat();

        let (key, nonce) =
            self.gen_key_and_nonce(&self.client_traffic_secret, record.get_sequence_number());

        let encrypted = self
            .get_ciphersuite()
            .encrypt(&key, &inner_plaintext, &nonce, &aad);

        TlsRecord::ApplicationData(encrypted, record.get_sequence_number())
    }

    pub fn decrypt_record(&mut self, record: &TlsRecord) -> Result<TlsRecord> {
        assert!(matches!(record, TlsRecord::ApplicationData(_, _)));
        if let TlsRecord::ApplicationData(encrypted, _) = record {
            let aad = record.get_additional_data();
            let (key, nonce) =
                self.gen_key_and_nonce(&self.server_traffic_secret, record.get_sequence_number());

            let decrypted = self
                .get_ciphersuite()
                .decrypt(&key, encrypted, &nonce, &aad);

            let rec = TlsRecord::parse_inner_plaintext(&decrypted)?;

            if rec.to_tls_vec()[5..] != decrypted[..(decrypted.len() - 1)] {
                println!("[-] Buggy implementation (parse_inner_plaintext)");
                dbg!(&rec);
                dbg!(&rec.to_tls_vec()[5..]);
                dbg!(decrypted);
                panic!();
            }
            Ok(rec)
        } else {
            unreachable!();
        }
    }

    pub fn get_verify_data(&self) -> Vec<u8> {
        self.compute_finished(&self.client_traffic_secret, &self.context)
    }

    pub fn compute_psk_binder(&self, truncated_client_hello: &[u8]) -> Vec<u8> {
        let binder_key = self.get_ciphersuite().derive_secret(
            self.early_secret.as_ref().unwrap(),
            "ext binder",
            &[],
        );

        self.compute_finished(&binder_key, truncated_client_hello)
    }

    fn compute_finished(&self, base_key: &[u8], context: &[u8]) -> Vec<u8> {
        let cs = self.get_ciphersuite();
        let transcript_hash = cs.hash(context.to_vec());

        let finished_key = cs.hkdf_expand_label(base_key, "finished", &[], cs.hash_length());

        cs.hmac(&finished_key, &transcript_hash)
    }

    // [RFC8446] Section 7.3 "Traffic Key Calculation"
    fn gen_key_and_nonce(&self, secret: &[u8], seq: u64) -> (Vec<u8>, Vec<u8>) {
        let cs = self.get_ciphersuite();
        let key = cs.hkdf_expand_label(secret, "key", &[], cs.key_length());
        let iv = cs.hkdf_expand_label(secret, "iv", &[], cs.iv_length());

        let nonce = seq.to_be_bytes();
        let mut nonce = [vec![0; iv.len() - nonce.len()], nonce.to_vec()].concat();
        for i in 0..nonce.len() {
            nonce[i] ^= iv[i];
        }

        (key, nonce)
    }

    // [RFC8446, p.93] Section 7.1 "Key Schedule"
    fn update_early_secret(&mut self) {
        let zero = self.zero_vector();
        let psk = if let Some(psk) = self.psk.as_ref() {
            psk
        } else {
            &zero
        };
        self.early_secret = Some(self.get_ciphersuite().hkdf_extract(&zero, psk));
    }

    // [RFC8446, p.93] Section 7.1 "Key Schedule"
    fn update_handshake_secret(&mut self) {
        let cs = self.get_ciphersuite();
        let shared_secret = self
            .shared_secret
            .as_ref()
            .unwrap()
            .raw_secret_bytes()
            .as_slice();
        let derived = cs.derive_secret(self.early_secret.as_ref().unwrap(), "derived", &[]);
        let hs_secret = cs.hkdf_extract(&derived, shared_secret);
        let cts = cs.derive_secret(&hs_secret, "c hs traffic", &self.current_context);
        let sts = cs.derive_secret(&hs_secret, "s hs traffic", &self.current_context);

        self.client_traffic_secret = cts;
        self.server_traffic_secret = sts;
        self.handshake_secret = Some(hs_secret);
    }

    // [RFC8446, p.93] Section 7.1 "Key Schedule"
    fn update_application_secret(&mut self) {
        let cs = self.get_ciphersuite();
        let master_secret = cs.hkdf_extract(
            &cs.derive_secret(self.handshake_secret.as_ref().unwrap(), "derived", &[]),
            &self.zero_vector(),
        );

        let cts = cs.derive_secret(&master_secret, "c ap traffic", &self.current_context);
        let sts = cs.derive_secret(&master_secret, "s ap traffic", &self.current_context);

        self.client_traffic_secret = cts;
        self.server_traffic_secret = sts;
    }

    fn zero_vector(&self) -> Vec<u8> {
        vec![0u8; self.get_ciphersuite().hash_length()]
    }

    fn get_ciphersuite(&self) -> &CipherSuite {
        self.cipher_suite
            .as_ref()
            .expect("Cipher Suite doesn't set")
    }
}
