#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::large_enum_variant)]
#![deny(warnings)]

#[cfg(all(feature = "aarch64", feature = "wasm32"))]
compile_error!("Feature \"aarch64\" can't be combined with \"wasm32\".");

pub mod errors;
pub mod mnemonic;
pub mod private;
pub mod public;

pub type Result<T> = core::result::Result<T, errors::Error>;
pub type SignatureBytes = [u8; LEN_SIGNATURE];
pub type SharedKeyBytes = [u8; LEN_SHARED_KEY];

pub const LEN_SHARED_KEY: usize = 64;
pub const LEN_SIGNATURE: usize = 64;
pub const SIGNING_CONTEXT_SR25519: &[u8] = b"substrate";

#[derive(Clone)]
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub enum CryptographicIdentity {
    OwnedKey {
        private: crate::private::PrivateKey,
        #[zeroize(skip)]
        public_edward: crate::public::PublicKey,
        #[zeroize(skip)]
        public_schnorrkel: crate::public::PublicKey,
    },
    OthersKey {
        #[zeroize(skip)]
        public: crate::public::PublicKey,
    },
}

impl core::hash::Hash for CryptographicIdentity {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::OwnedKey {
                public_schnorrkel, ..
            } => public_schnorrkel.hash(state),
            Self::OthersKey {
                public,
            } => public.hash(state),
        }
    }
}

impl core::convert::From<crate::private::PrivateKey> for CryptographicIdentity {
    fn from(value: crate::private::PrivateKey) -> Self {
        let public_edward = value.get_publickey_ed25519();
        let public_schnorrkel = value.get_publickey_sr25519();

        Self::OwnedKey {
            private: value,
            public_edward,
            public_schnorrkel,
        }
    }
}

impl core::convert::From<crate::public::PublicKey> for CryptographicIdentity {
    fn from(value: crate::public::PublicKey) -> Self {
        Self::OthersKey {
            public: value,
        }
    }
}

impl CryptographicIdentity {
    pub fn generate() -> Self {
        crate::private::PrivateKey::generate().into()
    }

    pub fn try_from_public_bytes(source: &[u8]) -> Result<Self> {
        Ok(crate::public::PublicKey::try_from(source)?.into())
    }

    pub fn try_from_public_str(source: &str) -> Result<Self> {
        Ok(crate::public::PublicKey::try_from(source)?.into())
    }

    pub fn try_from_private_bytes(source: &[u8]) -> Result<Self> {
        Ok(crate::private::PrivateKey::try_from(source)?.into())
    }

    pub fn try_from_private_str(source: &str) -> Result<Self> {
        Ok(crate::private::PrivateKey::try_from(source)?.into())
    }

    pub fn is_owned(&self) -> bool {
        matches!(self, Self::OwnedKey { .. })
    }

    pub fn is_schnorrkel(&self) -> bool {
        match self {
            Self::OwnedKey {
                ..
            } => true,
            Self::OthersKey {
                public,
            } => public.is_schnorrkel(),
        }
    }

    pub fn try_sign(&self, with_schnorrkel: bool, message: &[u8]) -> Result<SignatureBytes> {
        match self {
            Self::OthersKey {
                ..
            } => Err(crate::errors::Error::SigningDenied),
            Self::OwnedKey {
                private, ..
            } => Ok(private.sign(with_schnorrkel, message)),
        }
    }

    pub fn verify(&self, signature_bytes: &[u8], message: &[u8]) -> Result<bool> {
        match self {
            Self::OthersKey {
                public,
            } => public.verify(signature_bytes, message),
            Self::OwnedKey {
                public_edward,
                public_schnorrkel,
                ..
            } => {
                let ed25519_verification = public_edward.verify(signature_bytes, message)?;
                let sr25519_verification = public_schnorrkel.verify(signature_bytes, message)?;

                Ok(ed25519_verification | sr25519_verification)
            }
        }
    }

    pub fn try_get_private_key(&self) -> Option<crate::private::PrivateKey> {
        match self {
            Self::OthersKey {
                ..
            } => None,
            Self::OwnedKey {
                private, ..
            } => Some(private.clone()),
        }
    }

    pub fn try_get_public_ed25519(&self) -> Option<crate::public::PublicKey> {
        match self {
            Self::OthersKey {
                public,
            } => {
                match public {
                    crate::public::PublicKey::Ed25519(_) => Some(*public),
                    crate::public::PublicKey::Sr25519(_) => None,
                    crate::public::PublicKey::ApparentlyBoth {
                        ed25519, ..
                    } => Some(crate::public::PublicKey::Ed25519(*ed25519)),
                }
            }
            Self::OwnedKey {
                public_edward, ..
            } => Some(*public_edward),
        }
    }

    pub fn try_get_public_sr25519(&self) -> Option<crate::public::PublicKey> {
        match self {
            Self::OthersKey {
                public,
            } => {
                match public {
                    crate::public::PublicKey::Ed25519(_) => None,
                    crate::public::PublicKey::Sr25519(_) => Some(*public),
                    crate::public::PublicKey::ApparentlyBoth {
                        sr25519, ..
                    } => Some(crate::public::PublicKey::Sr25519(*sr25519)),
                }
            }
            Self::OwnedKey {
                public_schnorrkel, ..
            } => Some(*public_schnorrkel),
        }
    }

    pub fn try_get_otherskey_ed25519(&self) -> Option<Self> {
        match self {
            Self::OwnedKey {
                public_edward, ..
            } => {
                Some(Self::OthersKey {
                    public: *public_edward,
                })
            }
            Self::OthersKey {
                public,
            } => {
                match public {
                    crate::public::PublicKey::Ed25519(_) => {
                        Some(Self::OthersKey {
                            public: *public,
                        })
                    }
                    crate::public::PublicKey::Sr25519(_) => None,
                    crate::public::PublicKey::ApparentlyBoth {
                        ed25519, ..
                    } => {
                        let public = ed25519.into();

                        Some(Self::OthersKey {
                            public,
                        })
                    }
                }
            }
        }
    }

    pub fn try_get_otherskey_sr25519(&self) -> Option<Self> {
        match self {
            Self::OwnedKey {
                public_schnorrkel, ..
            } => {
                Some(Self::OthersKey {
                    public: *public_schnorrkel,
                })
            }
            Self::OthersKey {
                public,
            } => {
                match public {
                    crate::public::PublicKey::Ed25519(_) => None,
                    crate::public::PublicKey::Sr25519(_) => {
                        Some(Self::OthersKey {
                            public: *public,
                        })
                    }
                    crate::public::PublicKey::ApparentlyBoth {
                        sr25519, ..
                    } => {
                        let public = sr25519.into();

                        Some(Self::OthersKey {
                            public,
                        })
                    }
                }
            }
        }
    }

    pub fn try_create_sending_key(&self, receiver_key: &Self) -> Result<SharedKeyBytes> {
        if !self.is_owned() {
            return Err(crate::errors::Error::SenderKeyIsNotOwnedOnSending);
        }

        if receiver_key.is_owned() {
            return Err(crate::errors::Error::ReceiverKeyIsOwnedOnSending);
        }

        if receiver_key.is_schnorrkel() {
            return Err(crate::errors::Error::SchnorrkelIsNotSupported);
        }

        let secret_key = self.try_get_private_key().unwrap();
        let public_key_bytes = receiver_key.try_get_public_ed25519().unwrap().to_bytes();
        let public_key_compressed = curve25519_dalek::edwards::CompressedEdwardsY(public_key_bytes);
        let public_key_point = public_key_compressed
            .decompress()
            .ok_or(crate::errors::Error::EdwardsPointDecompressionFailure)?;
        let secret_key_scalar = secret_key.get_edward_scalar();
        let shared_point = public_key_point * secret_key_scalar;
        let shared_point_compressed = shared_point.compress();
        let shared_point_bytes = shared_point_compressed.to_bytes();
        let sender_public_key_bytes = secret_key.get_publickey_ed25519().to_bytes();
        let mut shared_key = [0; LEN_SHARED_KEY];
        shared_key[..32].copy_from_slice(&sender_public_key_bytes);
        shared_key[32..].copy_from_slice(&shared_point_bytes);

        Ok(shared_key)
    }

    pub fn try_create_receiving_key(&self, sender_key: &Self) -> Result<SharedKeyBytes> {
        if !self.is_owned() {
            return Err(crate::errors::Error::ReceiverKeyIsNotOwnedOnReceiving);
        }

        if sender_key.is_owned() {
            return Err(crate::errors::Error::SenderKeyIsOwnedOnReceiving);
        }

        if sender_key.is_schnorrkel() {
            return Err(crate::errors::Error::SchnorrkelIsNotSupported);
        }

        let secret_key = self.try_get_private_key().unwrap();
        let public_key_bytes = sender_key.try_get_public_ed25519().unwrap().to_bytes();
        let public_key_compressed = curve25519_dalek::edwards::CompressedEdwardsY(public_key_bytes);
        let public_key_point = public_key_compressed
            .decompress()
            .ok_or(crate::errors::Error::EdwardsPointDecompressionFailure)?;
        let secret_key_scalar = secret_key.get_edward_scalar();
        let shared_point = public_key_point * secret_key_scalar;
        let shared_point_compressed = shared_point.compress();
        let shared_point_bytes = shared_point_compressed.to_bytes();
        let mut shared_key = [0; LEN_SHARED_KEY];
        shared_key[..32].copy_from_slice(&public_key_bytes);
        shared_key[32..].copy_from_slice(&shared_point_bytes);

        Ok(shared_key)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::private::PrivateKeyBytes;
    use alloc::format;
    use alloc::string::ToString;
    use core::ops::Deref;
    use hex::decode;
    use sp_core::crypto::Ss58Codec;
    use sp_core::ed25519::{Pair as Ed25519KeyPair, Public as Ed25519PublicKey, Signature as Ed25519Signature};
    use sp_core::sr25519::{Pair as Sr25519KeyPair, Public as Sr25519PublicKey, Signature as Sr25519Signature};
    use sp_core::Pair;
    use ss58_registry::Ss58AddressFormatRegistry;

    const ALICE_MINISECRET_HEX: &str = "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
    const ALICE_SS58_ED25519: &str = "gr2LLpGt2rLUixu5YzrWNvbX9qJeavgZLh95UpwBpvZSq6xpA";
    const ALICE_SS58_SR25519: &str = "gr5wupneKLGRBrA3hkcrXgbwXp1F26SV7L4LymGxCKs9QMXn1";
    const MESSAGE_HEX: &str = "600dd33d";
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_MNEMONIC_SS58_ED25519: &str = "gr4RyyaYMXAUDghwBPGePHhU8Muncg2UA3dGa7btdxySRBEge";
    const TEST_MNEMONIC_SS58_SR25519: &str = "gr3UANwp2xZ4DCsbGKaeNPEaUWfZSBqZZ2qM5Mmsm8UN3tWfz";
    const RANDOM_TEST_COUNT: usize = 128;

    #[test]
    fn alice_sr25519_signing_is_correct() {
        let substrate_pubkey = Sr25519PublicKey::from_ss58check(ALICE_SS58_SR25519).unwrap();
        let signer = CryptographicIdentity::try_from_private_str(ALICE_MINISECRET_HEX).unwrap();
        let message_bytes = decode(MESSAGE_HEX).unwrap();
        let signature = signer.try_sign(true, &message_bytes).unwrap();
        let substrate_signature = Sr25519Signature::from_slice(&signature).unwrap();

        assert!(Sr25519KeyPair::verify(
            &substrate_signature,
            &message_bytes,
            &substrate_pubkey
        ));
    }

    #[test]
    fn alice_ed25519_signing_is_correct() {
        let substrate_pubkey = Ed25519PublicKey::from_ss58check(ALICE_SS58_ED25519).unwrap();
        let signer = CryptographicIdentity::try_from_private_str(ALICE_MINISECRET_HEX).unwrap();
        let message_bytes = decode(MESSAGE_HEX).unwrap();
        let signature = signer.try_sign(false, &message_bytes).unwrap();
        let substrate_signature = Ed25519Signature::from_slice(&signature).unwrap();

        assert!(Ed25519KeyPair::verify(
            &substrate_signature,
            &message_bytes,
            &substrate_pubkey
        ));
    }

    #[test]
    fn alice_sr25519_ss58_is_correct() {
        let signer = CryptographicIdentity::try_from_private_str(ALICE_MINISECRET_HEX).unwrap();
        let sr25519_pubkey = signer.try_get_public_sr25519().unwrap();
        let sr25519_ss58 = format!("{}", sr25519_pubkey.get_main_address());

        assert_eq!(sr25519_ss58, ALICE_SS58_SR25519);
    }

    #[test]
    fn alice_ed25519_ss58_is_correct() {
        let signer = CryptographicIdentity::try_from_private_str(ALICE_MINISECRET_HEX).unwrap();
        let ed25519_pubkey = signer.try_get_public_ed25519().unwrap();
        let ed25519_ss58 = format!("{}", ed25519_pubkey.get_main_address());

        assert_eq!(ed25519_ss58, ALICE_SS58_ED25519);
    }

    #[test]
    fn sr25519_generate_from_mnemonic_is_correct() {
        let (substrate_identity, _) = Sr25519KeyPair::from_phrase(TEST_MNEMONIC, None).unwrap();
        let substrate_identity = substrate_identity.public();
        let substrate_identity =
            substrate_identity.to_ss58check_with_version(Ss58AddressFormatRegistry::NagaraAccount.into());
        let identity = CryptographicIdentity::try_from_private_str(TEST_MNEMONIC).unwrap();
        let sr25519_address = identity.try_get_public_sr25519().unwrap().get_main_address();

        assert_eq!(sr25519_address.as_str(), TEST_MNEMONIC_SS58_SR25519);
        assert_eq!(sr25519_address.as_str(), substrate_identity);
    }

    #[test]
    fn ed25519_generate_from_mnemonic_is_correct() {
        let (substrate_identity, _) = Ed25519KeyPair::from_phrase(TEST_MNEMONIC, None).unwrap();
        let substrate_identity = substrate_identity.public();
        let substrate_identity =
            substrate_identity.to_ss58check_with_version(Ss58AddressFormatRegistry::NagaraAccount.into());
        let identity = CryptographicIdentity::try_from_private_str(TEST_MNEMONIC).unwrap();
        let ed25519_address = identity.try_get_public_ed25519().unwrap().get_main_address();

        assert_eq!(ed25519_address.as_str(), TEST_MNEMONIC_SS58_ED25519);
        assert_eq!(ed25519_address.as_str(), substrate_identity);
    }

    #[test]
    fn many_random_sr25519_is_generated_correctly() {
        for _ in 0..RANDOM_TEST_COUNT {
            let random_mnemonic = crate::mnemonic::MnemonicPhrase::generate();
            let error_message = format!("Error on mnemonic: \"{}\"", random_mnemonic.deref());
            let (substrate_sr25519_keypair, substrate_secret_seed_bytes) =
                Sr25519KeyPair::from_phrase(&random_mnemonic, None).expect(&error_message);
            let substrate_nagara_ss58 = substrate_sr25519_keypair
                .public()
                .to_ss58check_with_version(Ss58AddressFormatRegistry::NagaraAccount.into());
            let substrate_sr25519_public_bytes = substrate_sr25519_keypair.public().0;
            let nagara_keypair = CryptographicIdentity::try_from_private_str(&random_mnemonic).expect(&error_message);
            let nagara_private_key_bytes = PrivateKeyBytes::from(nagara_keypair.try_get_private_key().unwrap());
            let nagara_sr25519_public_key = nagara_keypair.try_get_public_sr25519().unwrap();
            let nagara_ss58 = nagara_sr25519_public_key.get_main_address();
            let nagara_sr25519_public_bytes = nagara_sr25519_public_key.to_bytes();

            assert_eq!(nagara_private_key_bytes, substrate_secret_seed_bytes);
            assert_eq!(nagara_sr25519_public_bytes, substrate_sr25519_public_bytes);
            assert_eq!(nagara_ss58.to_string(), substrate_nagara_ss58);
        }
    }

    #[test]
    fn many_random_ed25519_is_generated_correctly() {
        for _ in 0..RANDOM_TEST_COUNT {
            let random_mnemonic = crate::mnemonic::MnemonicPhrase::generate();
            let error_message = format!("Error on mnemonic: \"{}\"", random_mnemonic.deref());
            let (substrate_ed25519_keypair, substrate_secret_seed_bytes) =
                Ed25519KeyPair::from_phrase(&random_mnemonic, None).expect(&error_message);
            let substrate_nagara_ss58 = substrate_ed25519_keypair
                .public()
                .to_ss58check_with_version(Ss58AddressFormatRegistry::NagaraAccount.into());
            let substrate_ed25519_public_bytes = substrate_ed25519_keypair.public().0;
            let nagara_keypair = CryptographicIdentity::try_from_private_str(&random_mnemonic).expect(&error_message);
            let nagara_private_key_bytes = PrivateKeyBytes::from(nagara_keypair.try_get_private_key().unwrap());
            let nagara_ed25519_public_key = nagara_keypair.try_get_public_ed25519().unwrap();
            let nagara_ss58 = nagara_ed25519_public_key.get_main_address();
            let nagara_ed25519_public_bytes = nagara_keypair.try_get_public_ed25519().unwrap().to_bytes();

            assert_eq!(nagara_private_key_bytes, substrate_secret_seed_bytes);
            assert_eq!(nagara_ed25519_public_bytes, substrate_ed25519_public_bytes);
            assert_eq!(nagara_ss58.to_string(), substrate_nagara_ss58);
        }
    }
}
