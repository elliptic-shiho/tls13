pub mod tls;

pub use crate::tls::Error;

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let rng = rand::thread_rng();
    let mut client = tls::Client::open("0.0.0.0", 50000, rng)?;

    client.handshake()?;
    client.send_tls_message(b"Hello, World!\n")?;
    Ok(())
}
