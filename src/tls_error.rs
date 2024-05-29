#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    TlsError(String),
}

macro_rules! error_impl {
    ($name:ident, $t:ty) => {
        impl From<$t> for Error {
            fn from(err: $t) -> Self {
                Error::$name(err)
            }
        }
    };
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::IoError(err) => write!(f, "{}", err),
            Self::TlsError(err) => write!(f, "{}", err),
        }
    }
}

error_impl!(IoError, std::io::Error);
