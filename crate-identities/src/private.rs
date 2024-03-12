pub type PrivateKeyBytes = [u8; PrivateKey::LEN_PRIVATE_KEY];

#[derive(core::cmp::Eq, core::cmp::PartialEq)]
#[derive(core::cmp::PartialOrd, core::cmp::Ord)]
#[derive(core::clone::Clone, core::hash::Hash)]
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PrivateKey {
    inner: PrivateKeyBytes,
}

impl core::convert::From<PrivateKeyBytes> for PrivateKey {
    fn from(value: PrivateKeyBytes) -> Self {
        Self {
            inner: value,
        }
    }
}

impl core::convert::From<PrivateKey> for PrivateKeyBytes {
    fn from(value: PrivateKey) -> Self {
        value.inner
    }
}

impl core::convert::TryFrom<&str> for PrivateKey {
    type Error = crate::errors::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let result_from_hex = Self::try_from_hex(value);
        let result_from_mnemonic = Self::try_from_phrase(value, "");

        match (result_from_hex, result_from_mnemonic) {
            (Err(_), Err(_)) => Err(crate::errors::Error::InvalidPrivateKeyString),
            (Ok(result), _) => Ok(result),
            (_, Ok(result)) => Ok(result),
        }
    }
}

impl core::convert::TryFrom<&[u8]> for PrivateKey {
    type Error = crate::errors::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let source_len = value.len();

        if source_len != Self::LEN_PRIVATE_KEY {
            Err(crate::errors::Error::InvalidByteLength)
        } else {
            let mut inner = PrivateKeyBytes::default();
            inner.copy_from_slice(value);

            Ok(Self {
                inner,
            })
        }
    }
}

impl core::convert::From<nagara_mnemonic::MnemonicPhrase> for PrivateKey {
    fn from(value: nagara_mnemonic::MnemonicPhrase) -> Self {
        let secret_seed = value.try_get_secret_seed("").expect("Infallible");
        let mut inner = PrivateKeyBytes::default();
        inner.copy_from_slice(&secret_seed[..Self::LEN_PRIVATE_KEY]);

        Self {
            inner,
        }
    }
}

impl PrivateKey {
    pub const EXPANSION_MODE_SR25519: schnorrkel::ExpansionMode = schnorrkel::MiniSecretKey::ED25519_MODE;
    pub const LEN_PRIVATE_KEY: usize = 32;

    pub fn generate() -> Self {
        let mut inner = PrivateKeyBytes::default();
        let _ = getrandom::getrandom(&mut inner);

        Self {
            inner,
        }
    }

    pub fn try_from_hex(source: &str) -> crate::Result<Self> {
        let sanitized_maybe_hex = if let Some(supposedly_hex_str) = source.strip_prefix("0x") {
            supposedly_hex_str
        } else {
            source
        };

        if sanitized_maybe_hex.len() != Self::LEN_PRIVATE_KEY * 2 {
            return Err(crate::errors::Error::InvalidHexLength);
        }

        let mut inner = PrivateKeyBytes::default();
        hex::decode_to_slice(sanitized_maybe_hex, &mut inner).map_err(|_| crate::errors::Error::InvalidHexCharacter)?;

        Ok(Self {
            inner,
        })
    }

    pub fn try_from_phrase(source: &str, password: &str) -> crate::Result<Self> {
        let mnemonic_phrase = nagara_mnemonic::MnemonicPhrase::try_from(source).map_err(crate::Error::from)?;
        let secret_seed = mnemonic_phrase
            .try_get_secret_seed(password)
            .map_err(crate::Error::from)?;
        let mut inner = PrivateKeyBytes::default();
        inner.copy_from_slice(&secret_seed[..Self::LEN_PRIVATE_KEY]);

        Ok(Self {
            inner,
        })
    }

    pub fn get_publickey_sr25519(&self) -> crate::public::PublicKey {
        let mini_secret = schnorrkel::MiniSecretKey::from_bytes(&self.inner).expect("Should be infallible!");
        let pubkey = mini_secret.expand_to_public(Self::EXPANSION_MODE_SR25519);

        crate::public::PublicKey::from(pubkey)
    }

    pub fn get_publickey_ed25519(&self) -> crate::public::PublicKey {
        let keypair = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(self.inner));

        crate::public::PublicKey::from(keypair.pk)
    }

    pub fn sign(&self, with_schnorrkel: bool, message: &[u8]) -> crate::SignatureBytes {
        if with_schnorrkel {
            let mini_secret = schnorrkel::MiniSecretKey::from_bytes(&self.inner).expect("Should be infallible");
            let keypair = mini_secret.expand_to_keypair(Self::EXPANSION_MODE_SR25519);

            keypair.sign_simple(crate::SIGNING_CONTEXT_SR25519, message).to_bytes()
        } else {
            let keypair = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(self.inner));
            let noise = ed25519_compact::Noise::generate();
            let signature = keypair.sk.sign(message, Some(noise));
            let mut signature_bytes = [0; crate::LEN_SIGNATURE];
            signature_bytes.copy_from_slice(signature.as_slice());

            signature_bytes
        }
    }
}
