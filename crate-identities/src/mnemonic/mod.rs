use bitvec::field::BitField;
use bitvec::view::BitView;
use core::str::FromStr;
use sha2::Digest;

mod mini_secret;
mod words;

pub const CHECKSUM_BIT: u8 = 4;
pub const LEN_ENTROPY_KDF_ROUND: usize = 2048;
pub const LEN_BITS_ENTROPY_CHUNK: usize = 11;
pub const LEN_ENTROPY: usize = 16;
pub const LEN_MAX_PASSWORD: usize = 512;
pub const LEN_SECRET_SEED: usize = 64;
pub const LEN_WORDS: usize = 12;
pub const LEN_PHRASE: usize = (words::LEN_WORD_MAX * LEN_WORDS) + LEN_WORDS - 1;

pub type SecretSeed = [u8; LEN_SECRET_SEED];
pub type Entropy = [u8; LEN_ENTROPY];

type MnemonicPhraseInner = arrayvec::ArrayString<{ LEN_PHRASE }>;

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct MnemonicPhrase {
    inner: MnemonicPhraseInner,
}

impl MnemonicPhrase {
    pub fn generate() -> Self {
        let mut inner = MnemonicPhraseInner::default();
        let mut entropy = zeroize::Zeroizing::new([0u8; { LEN_ENTROPY + 1 }]);
        getrandom::getrandom(entropy.as_mut_slice()).expect("Catastrophic failure on crypto system!");
        let checksum = (sha2::Sha256::digest(&entropy[0..LEN_ENTROPY])[0] >> 4) << 4;
        *entropy.last_mut().unwrap() = checksum;

        for slot in entropy
            .view_bits::<bitvec::prelude::Msb0>()
            .chunks_exact(LEN_BITS_ENTROPY_CHUNK)
        {
            let word_index = slot.load_be::<u16>() as usize;
            inner.push_str(words::MNEMONIC_WORDS[word_index]);
        }

        Self {
            inner,
        }
    }

    pub fn from_entropy(source: &[u8]) -> crate::Result<Self> {
        if source.len() != LEN_ENTROPY {
            return Err(crate::errors::Error::InvalidEntropyLength);
        }

        let mut inner = MnemonicPhraseInner::default();
        let mut entropy = zeroize::Zeroizing::new([0u8; { LEN_ENTROPY + 1 }]);
        entropy[0..LEN_ENTROPY].copy_from_slice(source);
        let checksum = (sha2::Sha256::digest(&entropy[0..LEN_ENTROPY])[0] >> 4) << 4;
        *entropy.last_mut().unwrap() = checksum;

        for slot in entropy
            .view_bits::<bitvec::prelude::Msb0>()
            .chunks_exact(LEN_BITS_ENTROPY_CHUNK)
        {
            let word_index = slot.load_be::<u16>() as usize;
            inner.push_str(words::MNEMONIC_WORDS[word_index]);
        }

        Ok(Self {
            inner,
        })
    }

    pub fn try_get_entropy(&self) -> crate::Result<zeroize::Zeroizing<Entropy>> {
        let mut entropy = zeroize::Zeroizing::new([0u8; { LEN_ENTROPY + 1 }]);
        let binary_view = entropy
            .view_bits_mut::<bitvec::prelude::Msb0>()
            .chunks_exact_mut(LEN_BITS_ENTROPY_CHUNK);

        for (word, entropy_chunk) in self.inner.split_whitespace().zip(binary_view) {
            let word_index = words::MNEMONIC_WORDS
                .binary_search(&word)
                .expect("Should be infallible!") as u16;
            entropy_chunk.store_be(word_index);
        }

        let checksum = (sha2::Sha256::digest(&entropy[0..LEN_ENTROPY])[0] >> 4) << 4;

        if checksum != entropy[LEN_ENTROPY] {
            return Err(crate::errors::Error::MemoryPoisoningDuringEntropyExtraction);
        }

        let mut revalidated_entropy = zeroize::Zeroizing::new(Entropy::default());
        revalidated_entropy.copy_from_slice(&entropy[0..LEN_ENTROPY]);

        Ok(revalidated_entropy)
    }
}

impl core::convert::TryFrom<&[&str]> for MnemonicPhrase {
    type Error = crate::errors::Error;

    fn try_from(value: &[&str]) -> Result<Self, Self::Error> {
        if value.len() != LEN_WORDS {
            return Err(crate::errors::Error::InvalidMnemonicWords);
        }

        let mut inner = MnemonicPhraseInner::default();

        for (index, word) in value.iter().enumerate() {
            if !words::MNEMONIC_WORDS.contains(word) {
                return Err(crate::errors::Error::InvalidMnemonicWords);
            }

            inner.push_str(word);

            if index + 1 < LEN_WORDS {
                inner.push(' ');
            }
        }

        Ok(Self {
            inner,
        })
    }
}

impl core::convert::TryFrom<&str> for MnemonicPhrase {
    type Error = crate::errors::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > LEN_PHRASE {
            return Err(crate::errors::Error::InvalidMnemonicWords);
        }

        let split_str = value.split_whitespace();
        let mut word_count = 0;

        for word in split_str {
            if !words::MNEMONIC_WORDS.contains(&word) {
                return Err(crate::errors::Error::InvalidMnemonicWords);
            }

            word_count += 1;
        }

        if word_count > LEN_WORDS {
            return Err(crate::errors::Error::InvalidMnemonicWords);
        }

        let inner = MnemonicPhraseInner::from_str(value).expect("Should be infallible");

        Ok(Self {
            inner,
        })
    }
}

impl core::ops::Deref for MnemonicPhrase {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.inner.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Deref;

    #[test_case::test_case(
        "universe universe universe universe universe universe universe universe universe universe universe universe",
        LEN_PHRASE ;
        "longest word is fit perfectly"
    )]
    #[test_case::test_case(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
        47 ;
        "shortest word correctly sized"
    )]
    fn mnemonic_phrase_length_is_correct(mnemonic_word: &str, expected_len: usize) {
        let mnemonic_phrase = MnemonicPhrase::try_from(mnemonic_word).unwrap();

        assert_eq!(mnemonic_phrase.len(), expected_len);
        assert_eq!(mnemonic_phrase.deref(), mnemonic_word);
    }
}
