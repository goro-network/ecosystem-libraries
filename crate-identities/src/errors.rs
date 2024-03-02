#[derive(parity_scale_codec::Decode, parity_scale_codec::Encode)]
#[derive(thiserror_no_std::Error, serde::Deserialize, serde::Serialize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(i32)]
pub enum Error {
    #[error(transparent)]
    MnemonicError(#[from] nagara_mnemonic::Error),
    #[error("Invalid hex length")]
    InvalidHexLength,
    #[error("Invalid hex character")]
    InvalidHexCharacter,
    #[error("Invalid byte length")]
    InvalidByteLength,
    #[error("Invalid public key bytes")]
    InvalidPublicKeyBytes,
    #[error("Invalid Ss58 string")]
    InvalidSs58String,
    #[error("Invalid signature length")]
    InvalidSignatureLength,
    #[error("Invalid signature format")]
    InvalidSignatureFormat,
    #[error("Invalid private key string")]
    InvalidPrivateKeyString,
    #[error("Signing is denied")]
    SigningDenied,
    #[error("Neither keys are owned")]
    NeitherKeysAreOwned,
    #[error("Schnorrkel is not supported for shared key generation")]
    SchnorrkelIsNotSupported,
    #[error("Weak public key is not supported for key exchange")]
    WeakEdwardPublicKey,
    #[error("Signature is not authentic")]
    SignatureIsNotAuthentic,
}
