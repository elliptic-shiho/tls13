pub mod tls;
mod tls_error;

pub use crate::tls_error::Error;

use p256::ecdh::EphemeralSecret;
use p256::EncodedPoint;
use rand::prelude::*;

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let mut rand_value = vec![0u8; 32];
    rng.fill_bytes(&mut rand_value);

    let secret = EphemeralSecret::random(&mut rng);
    let my_pk = EncodedPoint::from(secret.public_key());

    let mut client = tls::Client::open("0.0.0.0", 50000)?;

    use tls::extension_descriptor::*;
    let ch = tls::ClientHello::new(
        rand_value,
        vec![
            tls::CipherSuite::TLS_AES_128_GCM_SHA256,
            tls::CipherSuite::TLS_AES_256_GCM_SHA384,
        ],
        vec![
            tls::Extension::ServerName(ServerNameDescriptor {
                server_names: vec![ServerName::HostName("localhost".to_string())],
            }),
            tls::Extension::SignatureAlgorithms(SignatureAlgorithmsDescriptor {
                supported_signature_algorithms: vec![SignatureScheme::ecdsa_secp256r1_sha256],
            }),
            tls::Extension::SupportedVersions(SupportedVersionsDescriptor::ClientHello(vec![
                0x0304,
            ])),
            tls::Extension::SupportedGroups(SupportedGroupsDescriptor {
                named_group_list: vec![NamedGroup::secp256r1],
            }),
            tls::Extension::KeyShare(KeyShareDescriptor::ClientHello(vec![KeyShareEntry {
                group: NamedGroup::secp256r1,
                key_exchange: my_pk.to_bytes().to_vec(),
            }])),
        ],
    );
    client.send_handshake(tls::Handshake::ClientHello(ch))?;
    dbg!(client.recv()?);
    Ok(())
}
