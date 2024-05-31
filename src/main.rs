pub mod tls;
mod tls_error;

pub use crate::tls_error::Error;

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let rng = rand::thread_rng();
    let mut client = tls::Client::open("0.0.0.0", 50000, rng)?;
    // let mut client = tls::Client::open("github.com", 443, rng)?;

    dbg!(client.handshake()?);
    // client.send_tls_message(b"Hello, World!")?;
    dbg!(client.recv_tls_message()?);
    Ok(())
}
