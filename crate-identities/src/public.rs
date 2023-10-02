use blake2::Digest;
use core::str::FromStr;
use ed25519_dalek::Verifier;

pub type PublicKeyBytes = [u8; PublicKey::LEN_PUBLIC_KEY];
pub type Ss58String = arrayvec::ArrayString<{ PublicKey::SS58_STRING_MAX_LENGTH }>;

type Ed25519PublicKey = ed25519_dalek::VerifyingKey;
type Ed25519Signature = ed25519_dalek::Signature;
type Sr25519PublicKey = schnorrkel::PublicKey;
type Sr25519Signature = schnorrkel::Signature;

#[derive(core::clone::Clone, core::marker::Copy, core::cmp::Eq)]
pub enum PublicKey {
    Ed25519(Ed25519PublicKey),
    Sr25519(Sr25519PublicKey),
    ApparentlyBoth {
        ed25519: Ed25519PublicKey,
        sr25519: Sr25519PublicKey,
    },
}

impl core::cmp::PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl core::cmp::PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.as_ref().cmp(other.as_ref()))
    }
}

impl core::cmp::Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl core::hash::Hash for PublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl core::convert::From<Sr25519PublicKey> for PublicKey {
    fn from(value: Sr25519PublicKey) -> Self {
        Self::Sr25519(value)
    }
}

impl core::convert::From<Ed25519PublicKey> for PublicKey {
    fn from(value: Ed25519PublicKey) -> Self {
        Self::Ed25519(value)
    }
}

impl core::convert::From<&Sr25519PublicKey> for PublicKey {
    fn from(value: &Sr25519PublicKey) -> Self {
        Self::Sr25519(*value)
    }
}

impl core::convert::From<&Ed25519PublicKey> for PublicKey {
    fn from(value: &Ed25519PublicKey) -> Self {
        Self::Ed25519(*value)
    }
}

impl core::convert::AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(inner) => inner.as_ref(),
            Self::Sr25519(inner) => inner.as_ref(),
            Self::ApparentlyBoth {
                ed25519, ..
            } => ed25519.as_ref(),
        }
    }
}

impl core::convert::From<PublicKey> for PublicKeyBytes {
    fn from(value: PublicKey) -> Self {
        match value {
            PublicKey::Ed25519(inner) => inner.to_bytes(),
            PublicKey::Sr25519(inner) => inner.to_bytes(),
            PublicKey::ApparentlyBoth {
                ed25519, ..
            } => ed25519.to_bytes(),
        }
    }
}

impl core::convert::From<&PublicKey> for PublicKeyBytes {
    fn from(value: &PublicKey) -> Self {
        match value {
            PublicKey::Ed25519(inner) => inner.to_bytes(),
            PublicKey::Sr25519(inner) => inner.to_bytes(),
            PublicKey::ApparentlyBoth {
                ed25519, ..
            } => ed25519.to_bytes(),
        }
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.get_ss58_string(Self::PREFIX_DEFAULT))
    }
}

impl core::convert::TryFrom<&[u8]> for PublicKey {
    type Error = crate::errors::Error;

    fn try_from(value: &[u8]) -> core::result::Result<Self, Self::Error> {
        let source_len = value.len();

        if source_len != Self::LEN_PUBLIC_KEY {
            return Err(crate::errors::Error::InvalidByteLength);
        }

        let mut supposed_pubkey = PublicKeyBytes::default();
        supposed_pubkey.copy_from_slice(value);

        let maybe_sr25519 = Sr25519PublicKey::from_bytes(&supposed_pubkey[..]);
        let maybe_ed25519 = Ed25519PublicKey::from_bytes(&supposed_pubkey);

        match (maybe_sr25519, maybe_ed25519) {
            (Ok(sr25519), Ok(ed25519)) => {
                Ok(Self::ApparentlyBoth {
                    ed25519,
                    sr25519,
                })
            }
            (Err(_), Err(_)) => Err(crate::errors::Error::InvalidPublicKeyBytes),
            (Ok(sr25519), Err(_)) => Ok(Self::Sr25519(sr25519)),
            (Err(_), Ok(ed25519)) => Ok(Self::Ed25519(ed25519)),
        }
    }
}

impl core::convert::TryFrom<&str> for PublicKey {
    type Error = crate::errors::Error;

    fn try_from(value: &str) -> core::result::Result<Self, Self::Error> {
        if value.starts_with("0x") {
            let sanitized_value = value.strip_prefix("0x").unwrap();

            Self::try_from_hex_bytes(sanitized_value)
        } else {
            Self::try_from_ss58(value)
        }
    }
}

impl PublicKey {
    pub const LEN_PUBLIC_KEY: usize = 32;
    pub const PREFIX_DEFAULT: u16 = Self::PREFIX_GORO;
    pub const PREFIX_GORO: u16 = ss58_registry::Ss58AddressFormatRegistry::GoroAccount as u16;
    pub const PREFIX_KRIGAN: u16 = ss58_registry::Ss58AddressFormatRegistry::KriganAccount as u16;
    pub const PREFIX_SS58: &[u8; 7] = b"SS58PRE";
    pub const SS58_BYTES_LENGTH: usize = Self::LEN_PUBLIC_KEY + Self::SS58_BYTES_SUFFIX_PREFIX_LENGTH;
    pub const SS58_BYTES_PREFIX_LENGTH: usize = 2;
    pub const SS58_BYTES_SUFFIX_INDEX: usize = Self::SS58_BYTES_LENGTH - Self::SS58_BYTES_SUFFIX_LENGTH;
    pub const SS58_BYTES_SUFFIX_LENGTH: usize = 2;
    pub const SS58_BYTES_SUFFIX_PREFIX_LENGTH: usize =
        Self::SS58_BYTES_PREFIX_LENGTH + Self::SS58_BYTES_SUFFIX_LENGTH;
    pub const SS58_STRING_LENGTH_RANGE: core::ops::RangeInclusive<usize> =
        Self::SS58_STRING_MIN_LENGTH..=Self::SS58_STRING_MAX_LENGTH;
    pub const SS58_STRING_MAX_LENGTH: usize = 50;
    pub const SS58_STRING_MIN_LENGTH: usize = Self::SS58_BYTES_SUFFIX_PREFIX_LENGTH;

    pub fn get_ss58_string(&self, prefix: u16) -> Ss58String {
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(Self::PREFIX_SS58);
        let mut hash_buffer = [0u8; 64]; // 512-bit
        let mut string_buffer = [0u8; { Self::SS58_BYTES_LENGTH * 2 }];
        let mut version_buffer = [0u8; Self::SS58_BYTES_LENGTH];
        let ident: u16 = prefix & 0b0011_1111_1111_1111; // 14-bit only
        let sort_ident = (0..64).contains(&ident);
        let string_length;

        if sort_ident {
            version_buffer[0] = ident as u8;
            version_buffer[1..33].copy_from_slice(self.as_ref());
            hasher.update(&version_buffer[..33]);
            hasher.finalize_into((&mut hash_buffer).into());
            version_buffer[33..35].copy_from_slice(&hash_buffer[..2]);
            string_length = bs58::encode(&version_buffer[..35])
                .onto(string_buffer.as_mut())
                .unwrap();
        } else {
            let first = (((ident & 0b0000_0000_1111_1100) as u8) >> 2) | 0b01000000;
            let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
            version_buffer[0] = first | 0b01000000;
            version_buffer[1] = second;
            version_buffer[2..34].copy_from_slice(self.as_ref());
            hasher.update(&version_buffer[..34]);
            hasher.finalize_into((&mut hash_buffer).into());
            version_buffer[34..36].copy_from_slice(&hash_buffer[..2]);
            string_length = bs58::encode(&version_buffer[..])
                .onto(string_buffer.as_mut())
                .unwrap();
        }

        let utf8_str = core::str::from_utf8(&string_buffer[..string_length]).expect("Should be infallible!");

        Ss58String::from_str(utf8_str).expect("Should be infallible!")
    }

    pub fn get_goro_address(&self) -> Ss58String {
        self.get_ss58_string(Self::PREFIX_GORO)
    }

    pub fn get_krigan_address(&self) -> Ss58String {
        self.get_ss58_string(Self::PREFIX_KRIGAN)
    }

    pub fn try_from_hex_bytes(hex_bytes: &str) -> crate::Result<Self> {
        if hex_bytes.len() != Self::LEN_PUBLIC_KEY * 2 {
            return Err(crate::errors::Error::InvalidHexLength);
        }

        let mut inner = PublicKeyBytes::default();
        hex::decode_to_slice(hex_bytes, &mut inner).map_err(|_| crate::errors::Error::InvalidHexCharacter)?;

        Self::try_from(&inner[..])
    }

    pub fn try_from_ss58(ss58_string: &str) -> crate::Result<Self> {
        let char_count = ss58_string.len();

        if !Self::SS58_STRING_LENGTH_RANGE.contains(&char_count) {
            return Err(crate::errors::Error::InvalidSs58String);
        }

        let mut hasher = blake2::Blake2b512::new();
        hasher.update(Self::PREFIX_SS58);
        let mut hash_buffer = [0u8; 64]; // 512-bit
        let mut decoded_buffer = [0u8; Self::SS58_BYTES_LENGTH];
        let decode_length = bs58::decode(ss58_string)
            .onto(&mut decoded_buffer)
            .map_err(|_| crate::errors::Error::InvalidSs58String)?;
        let mut inner = PublicKeyBytes::default();

        if (0..64).contains(&decoded_buffer[0]) {
            if decode_length != 35 {
                return Err(crate::errors::Error::InvalidSs58String);
            }

            hasher.update(&decoded_buffer[..33]);
            hasher.finalize_into((&mut hash_buffer).into());

            if hash_buffer[..2] != decoded_buffer[33..35] {
                return Err(crate::errors::Error::InvalidSs58String);
            }

            inner.copy_from_slice(&decoded_buffer[1..33]);
        } else {
            if decode_length != 36 {
                return Err(crate::errors::Error::InvalidSs58String);
            }

            hasher.update(&decoded_buffer[..34]);
            hasher.finalize_into((&mut hash_buffer).into());

            if hash_buffer[..2] != decoded_buffer[34..36] {
                return Err(crate::errors::Error::InvalidSs58String);
            }

            inner.copy_from_slice(&decoded_buffer[2..34]);
        }

        Self::try_from(&inner[..])
    }

    pub fn is_schnorrkel(&self) -> bool {
        matches!(self, Self::Sr25519(..) | Self::ApparentlyBoth { .. })
    }

    pub fn get_hex_string(&self) -> arrayvec::ArrayString<{ Self::LEN_PUBLIC_KEY * 2 }> {
        let bytes = self.as_ref();
        let mut output_buffer = [0; { Self::LEN_PUBLIC_KEY * 2 }];
        hex::encode_to_slice(bytes, &mut output_buffer).expect("Should be infallible!");
        let utf8_str = core::str::from_utf8(&output_buffer).expect("Should be infallible!");

        arrayvec::ArrayString::from_str(utf8_str).expect("Should be infallible!")
    }

    pub fn to_bytes(&self) -> PublicKeyBytes {
        self.into()
    }

    pub fn verify(&self, signature_bytes: &[u8], message: &[u8]) -> crate::Result<bool> {
        let signature_len = signature_bytes.len();

        if signature_len != crate::LEN_SIGNATURE {
            return Err(crate::errors::Error::InvalidSignatureLength);
        }

        match self {
            Self::Ed25519(inner) => {
                let signature = Ed25519Signature::from_slice(signature_bytes)
                    .map_err(|_| crate::errors::Error::InvalidSignatureFormat)?;

                Ok(inner.verify(message, &signature).is_ok())
            }
            Self::Sr25519(inner) => {
                let signature = Sr25519Signature::from_bytes(signature_bytes)
                    .map_err(|_| crate::errors::Error::InvalidSignatureFormat)?;

                Ok(inner
                    .verify_simple(crate::SIGNING_CONTEXT_SR25519, message, &signature)
                    .is_ok())
            }
            Self::ApparentlyBoth {
                ed25519,
                sr25519,
            } => {
                let signature = Ed25519Signature::from_slice(signature_bytes)
                    .map_err(|_| crate::errors::Error::InvalidSignatureFormat)?;

                if ed25519.verify(message, &signature).is_ok() {
                    return Ok(true);
                }

                let signature = schnorrkel::Signature::from_bytes(signature_bytes)
                    .map_err(|_| crate::errors::Error::InvalidSignatureFormat)?;

                Ok(sr25519
                    .verify_simple(crate::SIGNING_CONTEXT_SR25519, message, &signature)
                    .is_ok())
            }
        }
    }

    pub fn verify_with_string_identity(
        string_identity: &str,
        signature: &[u8],
        message: &[u8],
    ) -> crate::Result<bool> {
        let instance = Self::try_from(string_identity)?;

        instance.verify(signature, message)
    }

    pub fn verify_with_bytes_identity(
        bytes_account: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> crate::Result<bool> {
        let instance = Self::try_from(bytes_account)?;

        instance.verify(signature, message)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::format;
    use sp_core::crypto::{AccountId32, Ss58Codec};
    use sp_core::ed25519::Pair as Ed25519KeyPair;
    use sp_core::sr25519::Pair as Sr25519KeyPair;
    use sp_core::Pair;

    const ALICE_MINISECRET_HEX: &str = "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
    const ALICE_SR25519_HEX: &str = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    const ALICE_SR25519_GORO: &str = "gr5wupneKLGRBrA3hkcrXgbwXp1F26SV7L4LymGxCKs9QMXn1";
    const ALICE_SR25519_KRIGAN: &str = "kRvkvFKT8tJDBBRizPdK1Efug3j7XRC5JFJJUJ1aMnzj6aXuB";
    const ALICE_ED25519_HEX: &str = "0x34602b88f60513f1c805d87ef52896934baf6a662bc37414dbdbf69356b1a691";
    const ALICE_ED25519_GORO: &str = "gr2LLpGt2rLUixu5YzrWNvbX9qJeavgZLh95UpwBpvZSq6xpA";
    const ALICE_ED25519_KRIGAN: &str = "kRs9MEogrQNGiJAkqdrxrUfVJ52X6FS9XcP2yMfozPh2XKjFN";
    const ALICE_MESSAGE: &[u8] = b"Hello, this is Alice!";

    #[test]
    fn encode_alice_goro_is_correct() {
        let sr25519_pubkey = PublicKey::try_from(ALICE_SR25519_HEX).unwrap();
        let ed25519_pubkey = PublicKey::try_from(ALICE_ED25519_HEX).unwrap();
        let sr25519_goro = sr25519_pubkey.get_goro_address();
        let ed25519_goro = ed25519_pubkey.get_goro_address();
        let sr25519_substrate_account = AccountId32::from_ss58check(&sr25519_goro).unwrap();
        let ed25519_substrate_account = AccountId32::from_ss58check(&ed25519_goro).unwrap();
        let sr25519_substrate_hex = format!("0x{}", hex::encode(sr25519_substrate_account));
        let ed25519_substrate_hex = format!("0x{}", hex::encode(ed25519_substrate_account));

        assert_eq!(sr25519_goro.as_str(), ALICE_SR25519_GORO);
        assert_eq!(ed25519_goro.as_str(), ALICE_ED25519_GORO);
        assert_eq!(sr25519_substrate_hex, ALICE_SR25519_HEX);
        assert_eq!(ed25519_substrate_hex, ALICE_ED25519_HEX);
    }

    #[test]
    fn encode_alice_krigan_is_correct() {
        let sr25519_pubkey = PublicKey::try_from(ALICE_SR25519_HEX).unwrap();
        let ed25519_pubkey = PublicKey::try_from(ALICE_ED25519_HEX).unwrap();
        let sr25519_krigan = sr25519_pubkey.get_krigan_address();
        let ed25519_krigan = ed25519_pubkey.get_krigan_address();
        let sr25519_substrate_account = AccountId32::from_ss58check(&sr25519_krigan).unwrap();
        let ed25519_substrate_account = AccountId32::from_ss58check(&ed25519_krigan).unwrap();
        let sr25519_substrate_hex = format!("0x{}", hex::encode(sr25519_substrate_account));
        let ed25519_substrate_hex = format!("0x{}", hex::encode(ed25519_substrate_account));

        assert_eq!(sr25519_krigan.as_str(), ALICE_SR25519_KRIGAN);
        assert_eq!(ed25519_krigan.as_str(), ALICE_ED25519_KRIGAN);
        assert_eq!(sr25519_substrate_hex, ALICE_SR25519_HEX);
        assert_eq!(ed25519_substrate_hex, ALICE_ED25519_HEX);
    }

    #[test]
    fn decode_alice_goro_is_correct() {
        let sr25519_pubkey = PublicKey::try_from(ALICE_SR25519_GORO).unwrap();
        let ed25519_pubkey = PublicKey::try_from(ALICE_ED25519_GORO).unwrap();

        assert_eq!(sr25519_pubkey.get_goro_address().as_str(), ALICE_SR25519_GORO);
        assert_eq!(ed25519_pubkey.get_goro_address().as_str(), ALICE_ED25519_GORO);
        assert!(AccountId32::from_ss58check(ALICE_SR25519_GORO).is_ok());
        assert!(AccountId32::from_ss58check(ALICE_ED25519_GORO).is_ok());
    }

    #[test]
    fn decode_alice_krigan_is_correct() {
        let sr25519_pubkey = PublicKey::try_from(ALICE_SR25519_KRIGAN).unwrap();
        let ed25519_pubkey = PublicKey::try_from(ALICE_ED25519_KRIGAN).unwrap();

        assert_eq!(sr25519_pubkey.get_krigan_address().as_str(), ALICE_SR25519_KRIGAN);
        assert_eq!(ed25519_pubkey.get_krigan_address().as_str(), ALICE_ED25519_KRIGAN);
        assert!(AccountId32::from_ss58check(ALICE_SR25519_KRIGAN).is_ok());
        assert!(AccountId32::from_ss58check(ALICE_ED25519_KRIGAN).is_ok());
    }

    #[test]
    fn verify_alice_goro_verification_is_correct() {
        let sr25519_pubkey = PublicKey::try_from(ALICE_SR25519_GORO).unwrap();
        let ed25519_pubkey = PublicKey::try_from(ALICE_ED25519_GORO).unwrap();
        let substrate_sr25519_keypair = Sr25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let substrate_ed25519_keypair = Ed25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let signature_sr25519 = substrate_sr25519_keypair.sign(ALICE_MESSAGE);
        let signature_ed25519 = substrate_ed25519_keypair.sign(ALICE_MESSAGE);
        let signature_verification_sr25519 = sr25519_pubkey
            .verify(&signature_sr25519.0[..], ALICE_MESSAGE)
            .unwrap();
        let signature_verification_ed25519 = ed25519_pubkey
            .verify(&signature_ed25519.0[..], ALICE_MESSAGE)
            .unwrap();
        let signature_verification_anyhow_with_sr25519 = PublicKey::verify_with_string_identity(
            ALICE_SR25519_GORO,
            &signature_sr25519.0[..],
            ALICE_MESSAGE,
        )
        .unwrap();
        let signature_verification_anyhow_with_ed25519 = PublicKey::verify_with_string_identity(
            ALICE_ED25519_GORO,
            &signature_ed25519.0[..],
            ALICE_MESSAGE,
        )
        .unwrap();

        assert!(signature_verification_sr25519);
        assert!(signature_verification_ed25519);
        assert!(signature_verification_anyhow_with_sr25519);
        assert!(signature_verification_anyhow_with_ed25519);
    }

    #[test]
    fn verify_alice_krigan_verification_is_correct() {
        let sr25519_pubkey = PublicKey::try_from(ALICE_SR25519_KRIGAN).unwrap();
        let ed25519_pubkey = PublicKey::try_from(ALICE_ED25519_KRIGAN).unwrap();
        let substrate_sr25519_keypair = Sr25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let substrate_ed25519_keypair = Ed25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let signature_sr25519 = substrate_sr25519_keypair.sign(ALICE_MESSAGE);
        let signature_ed25519 = substrate_ed25519_keypair.sign(ALICE_MESSAGE);
        let signature_verification_sr25519 = sr25519_pubkey
            .verify(&signature_sr25519.0[..], ALICE_MESSAGE)
            .unwrap();
        let signature_verification_ed25519 = ed25519_pubkey
            .verify(&signature_ed25519.0[..], ALICE_MESSAGE)
            .unwrap();
        let signature_verification_anyhow_with_sr25519 = PublicKey::verify_with_string_identity(
            ALICE_SR25519_KRIGAN,
            &signature_sr25519.0[..],
            ALICE_MESSAGE,
        )
        .unwrap();
        let signature_verification_anyhow_with_ed25519 = PublicKey::verify_with_string_identity(
            ALICE_ED25519_KRIGAN,
            &signature_ed25519.0[..],
            ALICE_MESSAGE,
        )
        .unwrap();

        assert!(signature_verification_sr25519);
        assert!(signature_verification_ed25519);
        assert!(signature_verification_anyhow_with_sr25519);
        assert!(signature_verification_anyhow_with_ed25519);
    }
}
