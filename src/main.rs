pub mod tls;
mod tls_error;

pub use crate::tls_error::Error;

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let rng = rand::thread_rng();
    let mut client = tls::Client::open("0.0.0.0", 50000, rng)?;

    client.handshake()?;
    Ok(())
}
