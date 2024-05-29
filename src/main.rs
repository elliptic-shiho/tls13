pub mod tls;
mod tls_error;

pub use crate::tls_error::Error;

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let mut client = tls::Client::open("0.0.0.0", 50000)?;
    let ch = tls::ClientHello::new(
        vec![0; 32],
        vec![
            tls::CipherSuite::TLS_AES_128_GCM_SHA256,
            tls::CipherSuite::TLS_AES_256_GCM_SHA384,
        ],
        vec![
            tls::Extension::ServerName(tls::extension_descriptor::ServerNameDescriptor {
                server_names: vec![tls::extension_descriptor::ServerName::HostName(
                    "localhost".to_string(),
                )],
            }),
            tls::Extension::SignatureAlgorithms(
                tls::extension_descriptor::SignatureAlgorithmsDescriptor {
                    supported_signature_algorithms: vec![
                        tls::extension_descriptor::SignatureScheme::rsa_pkcs1_sha256,
                    ],
                },
            ),
            tls::Extension::SupportedVersions(
                tls::extension_descriptor::SupportedVersionsDescriptor::ClientHello(vec![0x0304]),
            ),
            tls::Extension::SupportedGroups(tls::extension_descriptor::SupportedGroupsDescriptor {
                named_group_list: vec![tls::extension_descriptor::NamedGroup::secp256r1],
            }),
            tls::Extension::KeyShare(tls::extension_descriptor::KeyShareDescriptor::ClientHello(
                vec![],
            )),
        ],
    );
    client.send_handshake(tls::Handshake::ClientHello(ch))?;
    dbg!(client.recv()?);
    Ok(())
}
