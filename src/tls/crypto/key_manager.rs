use crate::tls::extension_descriptor::KeyShareDescriptor;
use crate::tls::handshake::Certificate;
use crate::tls::{CipherSuite, Extension, Handshake, TlsRecord, ToTlsVec};
use crate::Result;
use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::{EncodedPoint, PublicKey};
use rand::prelude::*;
use x509_parser::prelude::*;

pub struct TlsKeyManager<T: CryptoRng + RngCore> {
    rng: Box<T>,
    client_random: Option<Vec<u8>>,
    server_random: Option<Vec<u8>>,
    cipher_suite: Option<CipherSuite>,
    client_ecdh_key: Option<EphemeralSecret>,
    shared_secret: Option<SharedSecret>,
    handshake_messages: Vec<Handshake>,
    psk: Option<Vec<u8>>,
    early_secret: Option<Vec<u8>>,
    handshake_secret: Option<Vec<u8>>,
    cert_type: CertificateType,
    server_cert: Option<Certificate>,
    server_handshake_context: Option<Vec<u8>>,
    client_traffic_secret: Option<Vec<u8>>,
    server_traffic_secret: Option<Vec<u8>>,
    finished_verify_data: Option<Vec<u8>>,
    client_traffic_secret_ap: Option<Vec<u8>>,
    server_traffic_secret_ap: Option<Vec<u8>>,
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
            client_random: None,
            server_random: None,
            cipher_suite: None,
            client_ecdh_key: None,
            shared_secret: None,
            handshake_messages: vec![],
            psk: None,
            early_secret: None,
            handshake_secret: None,
            cert_type: CertificateType::X509,
            server_cert: None,
            server_handshake_context: None,
            client_traffic_secret: None,
            server_traffic_secret: None,
            finished_verify_data: None,
            client_traffic_secret_ap: None,
            server_traffic_secret_ap: None,
        }
    }

    fn gen_random_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut rand_value = vec![0u8; n];
        self.rng.fill_bytes(&mut rand_value);
        rand_value
    }

    pub fn gen_client_pubkey(&mut self) -> EncodedPoint {
        self.client_ecdh_key = Some(EphemeralSecret::random(&mut self.rng));
        EncodedPoint::from(self.client_ecdh_key.as_ref().unwrap().public_key())
    }

    pub fn gen_client_random(&mut self) -> Vec<u8> {
        self.client_random = Some(self.gen_random_bytes(32));
        self.client_random.as_ref().unwrap().clone()
    }

    pub fn set_server_random(&mut self, server_random: Vec<u8>) {
        assert_eq!(server_random.len(), 32);
        self.server_random = Some(server_random)
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suite = Some(cipher_suite);
        if self.early_secret.is_none() && self.psk.is_none() {
            self.set_psk(self.zero_vector());
        }
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
    }

    pub fn handle_handshake_record_client(&mut self, hs: Handshake) {
        self.handshake_messages.push(hs.clone());
    }

    pub fn handle_handshake_record(&mut self, hs: Handshake) {
        self.handshake_messages.push(hs.clone());
        match &hs {
            Handshake::ServerHello(sh) => {
                self.set_server_random(sh.random.clone());
                self.set_cipher_suite(sh.cipher_suite.clone());
                for ext in &sh.extensions {
                    if let Extension::KeyShare(desc) = ext {
                        if let KeyShareDescriptor::ServerHello(entry) = desc {
                            self.set_server_pubkey(entry.key_exchange.clone());
                        } else {
                            dbg!(&sh);
                            panic!();
                        }
                    }
                }
                self.update_handshake_secret();
            }
            Handshake::EncryptedExtensions(ee) => {
                if !ee.is_empty() {
                    dbg!(ee);
                }
            }
            Handshake::Certificate(cert) => {
                match self.cert_type {
                    CertificateType::X509 => {
                        self.server_cert = Some(cert.clone());
                    }
                }
                let mut v = vec![];
                for msg in &self.handshake_messages {
                    v.push(msg.to_tls_vec());
                }
                self.server_handshake_context = Some(v.concat())
            }
            Handshake::CertificateVerify(cert_verify) => {
                // [RFC8446] Section 4.4.3 "CertificateVerify"
                let context = self.server_handshake_context.as_ref().unwrap().to_vec();
                let server_cert = self.server_cert.as_ref().unwrap();
                let transcript_hash = self.get_ciphersuite().hash(context.clone());
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
                self.server_handshake_context = Some(self.transcript_hash())
            }
            Handshake::Finished(fin) => {
                // [RFC8446] Section 4.4.4 "Finished"
                let cs = self.get_ciphersuite();
                let transcript_hash = self.server_handshake_context.as_ref().unwrap().to_vec();
                let server_finished_key = cs.hkdf_expand_label(
                    self.server_traffic_secret.as_ref().unwrap(),
                    "finished",
                    &[],
                    cs.hash_length(),
                );

                if cs.hmac(&server_finished_key, &transcript_hash) != fin.verify_data {
                    panic!("Failed to verify the server finished hmac");
                }

                let client_finished_key = cs.hkdf_expand_label(
                    self.client_traffic_secret.as_ref().unwrap(),
                    "finished",
                    &[],
                    cs.hash_length(),
                );

                let verify_data = cs.hmac(&client_finished_key, &self.transcript_hash());
                let master_secret = cs.hkdf_extract(
                    &self.derive_secret_with_empty_msg(
                        self.handshake_secret.as_ref().unwrap(),
                        "derived",
                    ),
                    &self.zero_vector(),
                );

                self.client_traffic_secret_ap =
                    Some(self.derive_secret(&master_secret, "c ap traffic"));
                self.server_traffic_secret_ap =
                    Some(self.derive_secret(&master_secret, "s ap traffic"));
                self.finished_verify_data = Some(verify_data);
            }
            x => {
                dbg!(&x);
            }
        }
    }

    pub fn encrypt_record(&mut self, record: &TlsRecord) -> TlsRecord {
        let inner_plaintext = record.unparse_inner_plaintext();
        let nonce = record.get_nonce();
        let aad = [
            vec![23, 3, 3],
            ((inner_plaintext.len() + self.get_ciphersuite().tag_length()) as u16).to_tls_vec(),
        ]
        .concat();

        TlsRecord::ApplicationData(
            self.encrypt_raw(&inner_plaintext, &nonce, &aad),
            record.get_sequence_number(),
        )
    }

    pub fn decrypt_record(&mut self, record: &TlsRecord) -> Result<TlsRecord> {
        assert!(matches!(record, TlsRecord::ApplicationData(_, _)));
        if let TlsRecord::ApplicationData(encrypted, _) = record {
            let nonce = record.get_nonce();
            let aad = record.get_additional_data();

            let decrypted = self.decrypt_raw(encrypted, &nonce, &aad);
            let rec = TlsRecord::parse_inner_plaintext(&decrypted)?;

            if rec.to_tls_vec()[5..] != decrypted[..(decrypted.len() - 1)] {
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

    fn encrypt_raw(&mut self, plaintext: &[u8], nonce: &[u8], additional_data: &[u8]) -> Vec<u8> {
        let (key, iv) = self.gen_key_and_iv(self.client_traffic_secret.as_ref().unwrap());

        let mut nonce = [vec![0; iv.len() - nonce.len()], nonce.to_vec()].concat();
        for i in 0..nonce.len() {
            nonce[i] ^= iv[i];
        }

        self.get_ciphersuite()
            .encrypt(&key, plaintext, &nonce, additional_data)
    }

    fn decrypt_raw(&mut self, ciphertext: &[u8], nonce: &[u8], additional_data: &[u8]) -> Vec<u8> {
        let (key, iv) = self.gen_key_and_iv(self.server_traffic_secret.as_ref().unwrap());

        let mut nonce = [vec![0; iv.len() - nonce.len()], nonce.to_vec()].concat();
        for i in 0..nonce.len() {
            nonce[i] ^= iv[i];
        }

        self.get_ciphersuite()
            .decrypt(&key, ciphertext, &nonce, additional_data)
    }

    pub fn get_verify_data(&self) -> Vec<u8> {
        self.finished_verify_data.as_ref().unwrap().clone()
    }

    // [RFC8446] Section 7.3 "Traffic Key Calculation"
    fn gen_key_and_iv(&self, secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cs = self.get_ciphersuite();
        let key = cs.hkdf_expand_label(secret, "key", &[], cs.key_length());
        let iv = cs.hkdf_expand_label(secret, "iv", &[], cs.iv_length());

        (key, iv)
    }

    // [RFC8446, p.93] Section 7.1 "Key Schedule"
    fn update_early_secret(&mut self) {
        self.early_secret = Some(
            self.get_ciphersuite()
                .hkdf_extract(&self.zero_vector(), self.psk.as_ref().unwrap()),
        );
    }

    // [RFC8446, p.93] Section 7.1 "Key Schedule"
    fn update_handshake_secret(&mut self) {
        let shared_secret = self
            .shared_secret
            .as_ref()
            .unwrap()
            .raw_secret_bytes()
            .as_slice();
        let derived =
            self.derive_secret_with_empty_msg(self.early_secret.as_ref().unwrap(), "derived");
        let hs_secret = self.get_ciphersuite().hkdf_extract(&derived, shared_secret);
        self.client_traffic_secret = Some(self.derive_secret(&hs_secret, "c hs traffic"));
        self.server_traffic_secret = Some(self.derive_secret(&hs_secret, "s hs traffic"));
        self.handshake_secret = Some(hs_secret);
    }

    pub fn finish_handshake(&mut self) {
        let cts_ap = self.client_traffic_secret_ap.as_ref().unwrap().clone();
        let sts_ap = self.server_traffic_secret_ap.as_ref().unwrap().clone();
        self.client_traffic_secret = Some(cts_ap);
        self.server_traffic_secret = Some(sts_ap);
        self.client_traffic_secret_ap = None;
        self.server_traffic_secret_ap = None;
    }

    // [RFC8446, p.91] Section 7.1 "Key Schedule"
    fn derive_secret_with_empty_msg(&self, secret: &[u8], label: &str) -> Vec<u8> {
        self.get_ciphersuite().hkdf_expand_label(
            secret,
            label,
            &self.get_ciphersuite().hash(vec![]),
            self.get_ciphersuite().hash_length(),
        )
    }

    // [RFC8446, p.91] Section 7.1 "Key Schedule"
    fn derive_secret(&self, secret: &[u8], label: &str) -> Vec<u8> {
        self.get_ciphersuite().hkdf_expand_label(
            secret,
            label,
            &self.transcript_hash(),
            self.get_ciphersuite().hash_length(),
        )
    }

    // [RFC8446, p.63] Section 4.4.1 "The Transcript Hash"
    fn transcript_hash(&self) -> Vec<u8> {
        let mut v = vec![];
        for hs in &self.handshake_messages {
            v.push(hs.to_tls_vec());
        }
        self.get_ciphersuite().hash(v.concat())
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
