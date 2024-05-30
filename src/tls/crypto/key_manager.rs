use crate::tls::extension_descriptor::KeyShareDescriptor;
use crate::tls::{CipherSuite, Extension, Handshake, ToTlsVec};
use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::{EncodedPoint, PublicKey};
use rand::prelude::*;

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
    client_handshake_traffic_secret: Option<Vec<u8>>,
    server_handshake_traffic_secret: Option<Vec<u8>>,
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
            client_handshake_traffic_secret: None,
            server_handshake_traffic_secret: None,
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
            Handshake::ClientHello(_) => {}
            x => {
                dbg!(&x);
            }
        }
    }

    pub fn decrypt_handshake(
        &mut self,
        ciphertext: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> Vec<u8> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes128Gcm, Key, Nonce};

        let key = self.get_ciphersuite().hkdf_expand_label(
            self.server_handshake_traffic_secret.as_ref().unwrap(),
            "key",
            &[],
            16,
        );
        let iv = self.get_ciphersuite().hkdf_expand_label(
            self.server_handshake_traffic_secret.as_ref().unwrap(),
            "iv",
            &[],
            12,
        );

        println!(
            "{:x?}",
            self.server_handshake_traffic_secret.as_ref().unwrap()
        );

        let mut nonce = [vec![0; iv.len() - nonce.len()], nonce.to_vec()].concat();
        for i in 0..nonce.len() {
            nonce[i] ^= iv[i];
        }

        let key = Key::<Aes128Gcm>::from_slice(&key);
        let cipher = Aes128Gcm::new(key);
        let payload = Payload {
            msg: ciphertext,
            aad: additional_data,
        };

        dbg!(cipher.decrypt(Nonce::from_slice(&nonce), payload));
        vec![]
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
        self.client_handshake_traffic_secret = Some(self.derive_secret(&hs_secret, "c hs traffic"));
        self.server_handshake_traffic_secret = Some(self.derive_secret(&hs_secret, "s hs traffic"));
        self.handshake_secret = Some(hs_secret);
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
