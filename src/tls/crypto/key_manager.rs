use crate::tls::CipherSuite;
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
}
