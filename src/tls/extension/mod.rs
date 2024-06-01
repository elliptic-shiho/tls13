pub mod descriptor;
#[allow(clippy::module_inception)]
mod extension;

pub use extension::Extension;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ExtensionSelector {
    ClientHello,
    ServerHello,
    HelloRetryRequest,
    EncryptedExtensions,
    Certificate,
    NewSessionTicket,
}
