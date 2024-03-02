#[derive(Clone)]
pub struct Decree {
    pub(crate) sequence: u64,
    pub(crate) sentinel: nagara_identities::public::PublicKey,
    pub(crate) big_brother: nagara_identities::public::PublicKey,
    pub(crate) big_brother_signature: nagara_identities::SignatureBytes,
    pub(crate) beneficiary: nagara_identities::public::PublicKey,
    pub(crate) object_hash: blake3::Hash,
    pub(crate) object_id: nagara_identities::public::PublicKey,
}

impl Decree {
    pub const LEN: usize = {
        core::mem::size_of::<u64>()
            + nagara_identities::public::PublicKey::LEN_PUBLIC_KEY
            + nagara_identities::public::PublicKey::LEN_PUBLIC_KEY
            + nagara_identities::LEN_SIGNATURE
            + nagara_identities::public::PublicKey::LEN_PUBLIC_KEY
            + blake3::OUT_LEN
            + nagara_identities::public::PublicKey::LEN_PUBLIC_KEY
    };
    pub const RANGE_0_SEQUENCE: core::ops::Range<usize> = 0..8;
    pub const RANGE_1_SENTINEL: core::ops::Range<usize> = 8..40;
    pub const RANGE_2_BIG_BROTHER: core::ops::Range<usize> = 40..72;
    pub const RANGE_3_BIG_BROTHER_SIGNATURE: core::ops::Range<usize> = 72..136;
    pub const RANGE_4_BENEFICIARY: core::ops::Range<usize> = 136..168;
    pub const RANGE_5_OBJECT_HASH: core::ops::Range<usize> = 168..200;
    pub const RANGE_6_OBJECT_ID: core::ops::Range<usize> = 200..Self::LEN;
}

impl crate::IAttestableDecree for Decree {
    fn beneficiary(&self) -> &nagara_identities::public::PublicKey {
        &self.beneficiary
    }

    fn big_brother(&self) -> &nagara_identities::public::PublicKey {
        &self.big_brother
    }

    fn big_brother_signature(&self) -> &nagara_identities::SignatureBytes {
        &self.big_brother_signature
    }

    fn object_hash(&self) -> &blake3::Hash {
        &self.object_hash
    }

    fn object_id(&self) -> &nagara_identities::public::PublicKey {
        &self.object_id
    }

    fn sentinel(&self) -> &nagara_identities::public::PublicKey {
        &self.sentinel
    }

    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn update_big_brother(&mut self, big_brother: nagara_identities::public::PublicKey) {
        self.big_brother = big_brother;
    }
}

impl crate::IBufferFormat for Decree {
    fn from_bytes(source: &[u8]) -> crate::Result<Self> {
        crate::ensure!(source.len() == Self::LEN, crate::Error::InvalidBufferLength);
        let slice_0_sequence = &source[Self::RANGE_0_SEQUENCE];
        let slice_1_sentinel = &source[Self::RANGE_1_SENTINEL];
        let slice_2_big_brother = &source[Self::RANGE_2_BIG_BROTHER];
        let slice_3_big_brother_signature = &source[Self::RANGE_3_BIG_BROTHER_SIGNATURE];
        let slice_4_beneficiary = &source[Self::RANGE_4_BENEFICIARY];
        let slice_5_object_hash = &source[Self::RANGE_5_OBJECT_HASH];
        let slice_6_object_id = &source[Self::RANGE_6_OBJECT_ID];
        let sequence_array = slice_0_sequence.try_into().unwrap();
        let hash_array = slice_5_object_hash.try_into().unwrap();
        let sequence = u64::from_le_bytes(sequence_array);
        let sentinel = nagara_identities::public::PublicKey::try_from(slice_1_sentinel)?;
        let big_brother = nagara_identities::public::PublicKey::try_from(slice_2_big_brother)?;
        let big_brother_signature = slice_3_big_brother_signature.try_into().unwrap();
        let beneficiary = nagara_identities::public::PublicKey::try_from(slice_4_beneficiary)?;
        let object_hash = blake3::Hash::from_bytes(hash_array);
        let object_id = nagara_identities::public::PublicKey::try_from(slice_6_object_id)?;

        Ok(Self {
            sequence,
            sentinel,
            big_brother,
            big_brother_signature,
            beneficiary,
            object_hash,
            object_id,
        })
    }

    fn into_bytes(&self, destination: &mut [u8]) -> crate::Result<()> {
        crate::ensure!(destination.len() == Self::LEN, crate::Error::InvalidBufferLength);
        destination[Self::RANGE_0_SEQUENCE].copy_from_slice(&self.sequence.to_le_bytes());
        destination[Self::RANGE_1_SENTINEL].copy_from_slice(self.sentinel.as_ref());
        destination[Self::RANGE_2_BIG_BROTHER].copy_from_slice(self.big_brother.as_ref());
        destination[Self::RANGE_3_BIG_BROTHER_SIGNATURE].copy_from_slice(&self.big_brother_signature);
        destination[Self::RANGE_4_BENEFICIARY].copy_from_slice(self.beneficiary.as_ref());
        destination[Self::RANGE_5_OBJECT_HASH].copy_from_slice(self.object_hash.as_bytes());
        destination[Self::RANGE_6_OBJECT_ID].copy_from_slice(self.object_id.as_ref());

        crate::Result::Ok(())
    }
}
