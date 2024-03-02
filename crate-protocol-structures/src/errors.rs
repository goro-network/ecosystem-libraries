#[macro_export]
macro_rules! ensure {
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err);
        }
    };
}

#[derive(core::fmt::Debug)]
#[derive(thiserror_no_std::Error)]
pub enum Error {
    #[error("UTF8 error")]
    UTF8Error(#[from] core::str::Utf8Error),
    #[error("Identity error")]
    IdentityError(#[from] nagara_identities::Error),
    #[error("GetRandom error")]
    GetRandom(#[from] getrandom::Error),
    #[error("Morus error")]
    Morus(#[from] morus::Error),
    #[error("Content integrity compromised")]
    ContentIntegrityCompromised,
    #[error("Decree object mismatch")]
    DecreeObjectMismatch,
    #[error("Schnorrkel is not supported")]
    SchnorrkelIsNotSupported,
    #[error("Object size is greater than maximum")]
    ObjectSizeExceeded,
    #[error("Invalid buffer length")]
    InvalidBufferLength,
    #[error("Invalid decree sentinel")]
    InvalidDecreeSentinel,
}
