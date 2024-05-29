#[macro_export]
macro_rules! impl_to_tls {
    ($($name:ident ($sel: ident) $bl:block)*) => {
        $(impl ToTlsVec for $name {
            fn to_tls_vec(&$sel) -> Vec<u8>
                $bl
        })*
    }
}

#[macro_export]
macro_rules! impl_from_tls {
    ($($name:ident ($var: ident) $bl:block)*) => {
        $(impl FromTlsVec for $name {
            fn from_tls_vec($var: &[u8]) -> Result<($name, &[u8])>
                $bl
        })*
    }
}

#[macro_export]
macro_rules! impl_from_tls_with_selector {
    ($($name:ident <$type:ty>($var: ident, $selector: ident) $bl:block)*) => {
        $(impl FromTlsVecWithSelector<$type> for $name {
            fn from_tls_vec<'a>($var: &'a [u8], $selector: &$type) -> Result<($name, &'a [u8])>
                $bl
        })*
    }
}

pub(crate) use impl_from_tls;
pub(crate) use impl_from_tls_with_selector;
pub(crate) use impl_to_tls;
