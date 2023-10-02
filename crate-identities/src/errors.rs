#[derive(parity_scale_codec::Decode, parity_scale_codec::Encode)]
#[derive(thiserror_no_std::Error, serde::Deserialize, serde::Serialize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Error {
    #[error("Invalid entropy length, must be 16 (12-words phrase)")]
    InvalidEntropyLength,
    #[error("Password too long, maximum password length is 512")]
    PasswordTooLong,
    #[error("Invalid mnemonic words")]
    InvalidMnemonicWords,
    #[error("Memory poisoning during entropy extraction")]
    MemoryPoisoningDuringEntropyExtraction,
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
}
