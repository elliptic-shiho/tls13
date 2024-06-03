pub mod tls;

pub use crate::tls::Error;

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let rng = rand::thread_rng();
    let mut client = tls::Client::open("0.0.0.0", 50000, rng)?;

    client.set_psk(b"ABC");
    client.handshake()?;
    client.send_tls_message(b"Hello, World!\n")?;
    println!(
        "[+] Response = {:?}",
        String::from_utf8_lossy(&client.recv_tls_message()?)
    );
    Ok(())
}
