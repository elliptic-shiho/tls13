pub mod tls;
mod tls_error;

pub use crate::tls_error::Error;

use tls::ToByteVec;

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let client = tls::Client::open("0.0.0.0", 50000);
    let ch = tls::ClientHello::new(
        vec![0; 32],
        vec![
            tls::CipherSuite::TLS_AES_128_GCM_SHA256,
            tls::CipherSuite::TLS_AES_256_GCM_SHA384,
        ],
        vec![
            tls::Extension::ServerName,
            tls::Extension::SupportedGroups,
            tls::Extension::SupportedVersions,
            tls::Extension::PskKeyExchangeModes,
            tls::Extension::KeyShare,
        ],
    );
    dbg!(ch.to_tls_vec());
    Ok(())
}
