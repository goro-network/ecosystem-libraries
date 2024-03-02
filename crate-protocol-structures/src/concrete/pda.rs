/// ## Permissioned Data
///
/// ### In Storing Form (User -> Ksatria):
/// - Sender is File ID
/// - Receiver is Sentinel/Keris ID
///
/// ### In Service Form (Ksatria -> User):
/// - Sender is Sentinel/Keris ID
/// - Receiver is Ephemeral Access ID as stated in a
///   [Decree](crate::IAttestableDecree) as
///   [Beneficiary](crate::IAttestableDecree::beneficiary)
///
/// ### In RAW/Bytes format:
/// - 0 -> 8 => identifier (ngr/pdaf), also a `derivation_context`;
/// - 8 -> 40 => sender: file id/sentinel id;
/// - 40 -> 72 => receiver: sentinel id/ephemeral access id;
/// - 72 -> 88 => morus's nonce;
/// - 88 -> 104 => morus's tag;
/// - 104 -> 136 => plain content's hash;
/// - 136 -> 168 => encrypted content's hash;
/// - 168 -> 172 => encrypted content's length (u32);
/// - 172 -> ... => encrypted content;
pub struct PermissionedData {
    sender: nagara_identities::public::PublicKey,   // 32 Bytes
    receiver: nagara_identities::public::PublicKey, // 32 Bytes
    nonce: morus::Nonce,                            // 16 Bytes
    tag: morus::Tag,                                // 16 Bytes
    hash_plain: blake3::Hash,                       // 32 Bytes
    hash_encrypted: blake3::Hash,                   // 32 Bytes
    encrypted_content: alloc::vec::Vec<u8>,         // IEncryptedEnvelope::LEN_MAX_CONTENT
}

impl PermissionedData {
    pub const DERIVATION_CONTEXT: &'static str = "ngr/pdaf";
    pub const DERIVATION_CONTEXT_BYTES: &'static [u8] = Self::DERIVATION_CONTEXT.as_bytes();
    pub const LEN_CIPHER_KEY: usize = core::mem::size_of::<morus::Key>();
    pub const LEN_HEADER: usize = 172;
    pub const RANGE_0_CONTEXT: core::ops::Range<usize> = 0..8;
    pub const RANGE_1_SENDER: core::ops::Range<usize> = 8..40;
    pub const RANGE_2_RECEIVER: core::ops::Range<usize> = 40..72;
    pub const RANGE_3_NONCE: core::ops::Range<usize> = 72..88;
    pub const RANGE_4_TAG: core::ops::Range<usize> = 88..104;
    pub const RANGE_5_HASH_PLAIN: core::ops::Range<usize> = 104..136;
    pub const RANGE_6_HASH_ENCRYPTED: core::ops::Range<usize> = 136..168;
    pub const RANGE_7_LEN_DATA: core::ops::Range<usize> = 168..172;
    pub const RANGE_DATA: core::ops::RangeFrom<usize> = Self::LEN_HEADER..;
}

impl crate::IBufferFormat for PermissionedData {
    fn from_bytes(source: &[u8]) -> crate::Result<Self> {
        crate::ensure!(source.len() > Self::LEN_HEADER, crate::Error::InvalidBufferLength);
        let slice_0_context = &source[Self::RANGE_0_CONTEXT];
        let slice_1_sender = &source[Self::RANGE_1_SENDER];
        let slice_2_receiver = &source[Self::RANGE_2_RECEIVER];
        let slice_3_nonce = &source[Self::RANGE_3_NONCE];
        let slice_4_tag = &source[Self::RANGE_4_TAG];
        let slice_5_hash_plain = &source[Self::RANGE_5_HASH_PLAIN];
        let slice_6_hash_encrypted = &source[Self::RANGE_6_HASH_ENCRYPTED];
        let slice_7_len_data = &source[Self::RANGE_7_LEN_DATA];
        let mut len_data_array = [0; 4];
        len_data_array.copy_from_slice(slice_7_len_data);
        let len_data = u32::from_le_bytes(len_data_array) as usize;
        let source_len = len_data + Self::LEN_HEADER;
        crate::ensure!(source.len() == source_len, crate::Error::InvalidBufferLength);
        crate::ensure!(
            slice_0_context == Self::DERIVATION_CONTEXT_BYTES,
            crate::Error::ContentIntegrityCompromised,
        );
        let sender = nagara_identities::public::PublicKey::try_from(slice_1_sender)?;
        let receiver = nagara_identities::public::PublicKey::try_from(slice_2_receiver)?;
        let nonce = slice_3_nonce.try_into().unwrap();
        let tag = slice_4_tag.try_into().unwrap();
        let hash_plain = blake3::Hash::from_bytes(slice_5_hash_plain.try_into().unwrap());
        let hash_encrypted = blake3::Hash::from_bytes(slice_6_hash_encrypted.try_into().unwrap());
        let encrypted_content = (&source[Self::RANGE_DATA]).to_vec();
        let computed_hash = blake3::hash(&encrypted_content);
        crate::ensure!(
            computed_hash.eq(&hash_encrypted),
            crate::Error::ContentIntegrityCompromised,
        );

        crate::Result::Ok(Self {
            sender,
            receiver,
            nonce,
            tag,
            hash_plain,
            hash_encrypted,
            encrypted_content,
        })
    }

    fn into_bytes(&self, destination: &mut [u8]) -> crate::Result<()> {
        let content_len = self.encrypted_content.len() as u32;
        let expected_len = Self::LEN_HEADER + (content_len as usize);
        crate::ensure!(destination.len() == expected_len, crate::Error::InvalidBufferLength);
        destination[Self::RANGE_0_CONTEXT].copy_from_slice(Self::DERIVATION_CONTEXT_BYTES);
        destination[Self::RANGE_1_SENDER].copy_from_slice(self.sender.as_ref());
        destination[Self::RANGE_2_RECEIVER].copy_from_slice(self.receiver.as_ref());
        destination[Self::RANGE_3_NONCE].copy_from_slice(&self.nonce);
        destination[Self::RANGE_4_TAG].copy_from_slice(&self.tag);
        destination[Self::RANGE_5_HASH_PLAIN].copy_from_slice(self.hash_plain.as_bytes());
        destination[Self::RANGE_6_HASH_ENCRYPTED].copy_from_slice(self.hash_encrypted.as_bytes());
        destination[Self::RANGE_7_LEN_DATA].copy_from_slice(&content_len.to_le_bytes());
        destination[Self::RANGE_DATA].copy_from_slice(&self.encrypted_content);

        crate::Result::Ok(())
    }
}

impl crate::IEncryptedEnvelope<crate::Decree> for PermissionedData {
    fn new_unchecked(
        sender: nagara_identities::public::PublicKey,
        receiver: nagara_identities::public::PublicKey,
        hash_encrypted: blake3::Hash,
        hash_plain: blake3::Hash,
        nonce: morus::Nonce,
        tag: morus::Tag,
        encrypted_content: alloc::vec::Vec<u8>,
    ) -> Self {
        Self {
            sender,
            receiver,
            hash_encrypted,
            hash_plain,
            nonce,
            tag,
            encrypted_content,
        }
    }

    fn derive_cipher_key(source: &[u8]) -> crate::Result<morus::Key> {
        let derived_key = blake3::derive_key(Self::DERIVATION_CONTEXT, source);
        let mut cipher_key = morus::Key::default();
        cipher_key.copy_from_slice(&derived_key[0..Self::LEN_CIPHER_KEY]);

        crate::Result::Ok(cipher_key)
    }

    fn encrypted_content(&self) -> &[u8] {
        &self.encrypted_content
    }

    fn hash_encrypted(&self) -> &blake3::Hash {
        &self.hash_encrypted
    }

    fn hash_plain(&self) -> &blake3::Hash {
        &self.hash_plain
    }

    fn nonce(&self) -> &morus::Nonce {
        &self.nonce
    }

    fn receiver(&self) -> &nagara_identities::public::PublicKey {
        &self.receiver
    }

    fn sender(&self) -> &nagara_identities::public::PublicKey {
        &self.sender
    }

    fn tag(&self) -> &morus::Tag {
        &self.tag
    }
}
