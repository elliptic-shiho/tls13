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
        vec![tls::Extension::ServerName(
            tls::extension_descriptor::ServerNameDescriptor {
                server_names: vec![tls::extension_descriptor::ServerName::HostName(
                    "localhost".to_string(),
                )],
            },
        )],
    );
    client.send_handshake(tls::Handshake::ClientHello(ch))?;
    dbg!(client.recv()?);
    Ok(())
}
