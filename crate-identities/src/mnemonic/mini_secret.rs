//! TODO: do proper SPDX for https://github.com/paritytech/substrate-bip39/blob/99bf393d15234b40ff0e440caee5b3cbce2b1732/src/lib.rs

use zeroize::Zeroize;

pub fn seed_from_entropy(entropy: &[u8], password: &str) -> crate::Result<super::SecretSeed> {
    let entropy_len = entropy.len();
    let password_len = password.len();

    if entropy_len != super::LEN_ENTROPY {
        return Err(crate::errors::Error::InvalidEntropyLength);
    }

    if password_len > super::LEN_MAX_PASSWORD {
        return Err(crate::errors::Error::PasswordTooLong);
    }

    let mut salt = arrayvec::ArrayString::<{ super::LEN_MAX_PASSWORD + 8 }>::new();
    salt.push_str("mnemonic");
    salt.push_str(password);
    let seed = pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, { super::LEN_SECRET_SEED }>(
        entropy,
        salt.as_bytes(),
        super::LEN_ENTROPY_KDF_ROUND as u32,
    );

    salt.zeroize();

    Ok(seed)
}

pub fn sr25519_mini_secret_from_entropy(
    entropy: &[u8],
    password: &str,
) -> crate::Result<schnorrkel::MiniSecretKey> {
    let seed = seed_from_entropy(entropy, password)?;

    Ok(
        schnorrkel::MiniSecretKey::from_bytes(&seed[..crate::private::PrivateKey::LEN_PRIVATE_KEY])
            .expect("Should be infallible!"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::{MnemonicPhrase, LEN_ENTROPY, LEN_SECRET_SEED};
    use test_case::test_case;

    const TEST_PASSWORD: &str = "Substrate";

    #[test_case(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "00000000000000000000000000000000",
        "44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e33f50c3d5c84fa3e5399c72d6cbbbbc4a49bf76f76d952f479d74655a2ef2d453" ;
        "entropy-00"
    )]
    #[test_case(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "4313249608fe8ac10fd5886c92c4579007272cb77c21551ee5b8d60b780416850f1e26c1f4b8d88ece681cb058ab66d6182bc2ce5a03181f7b74c27576b5c8bf" ;
        "entropy-7f"
    )]
    #[test_case(
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "80808080808080808080808080808080",
        "27f3eb595928c60d5bc91a4d747da40ed236328183046892ed6cd5aa9ae38122acd1183adf09a89839acb1e6eaa7fb563cc958a3f9161248d5a036e0d0af533d" ;
        "entropy-80"
    )]
    #[test_case(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ffffffffffffffffffffffffffffffff",
        "227d6256fd4f9ccaf06c45eaa4b2345969640462bbb00c5f51f43cb43418c7a753265f9b1e0c0822c155a9cabc769413ecc14553e135fe140fc50b6722c6b9df" ;
        "entropy-ff"
    )]

    fn vectors_from_12_words_are_correct(phrase: &str, entropy_hex: &str, seed_hex: &str) {
        let mut expected_entropy = [0; LEN_ENTROPY];
        let mut expected_seed = [0; LEN_SECRET_SEED];
        hex::decode_to_slice(entropy_hex, &mut expected_entropy).unwrap();
        hex::decode_to_slice(seed_hex, &mut expected_seed).unwrap();

        let mnemonic = MnemonicPhrase::try_from(phrase).unwrap();
        let entropy = mnemonic.try_get_entropy().unwrap();
        let seed = seed_from_entropy(&entropy[..], TEST_PASSWORD).unwrap();
        let secret_bytes = sr25519_mini_secret_from_entropy(&entropy[..], TEST_PASSWORD)
            .unwrap()
            .to_bytes();

        assert_eq!(&entropy[..], &expected_entropy[..]);
        assert_eq!(&seed[..], &expected_seed[..]);
        assert_eq!(
            &secret_bytes[..],
            &expected_seed[..crate::private::PrivateKey::LEN_PRIVATE_KEY]
        );
    }
}
