pub trait IAttestableDecree: Sized {
    /// To whom this decree will benefit
    fn beneficiary(&self) -> &nagara_identities::public::PublicKey;
    /// Big brother who sign this decree
    fn big_brother(&self) -> &nagara_identities::public::PublicKey;
    /// Big brother's signature
    fn big_brother_signature(&self) -> &nagara_identities::SignatureBytes;
    /// Object's hash (in its original form) in context
    fn object_hash(&self) -> &blake3::Hash;
    /// Object's ID
    fn object_id(&self) -> &nagara_identities::public::PublicKey;
    /// Sentinel's ID who will attest or react to this decree
    fn sentinel(&self) -> &nagara_identities::public::PublicKey;
    /// Decree's sequence, will be used as Sentinel's offset, this is to prevent
    /// replay attack
    fn sequence(&self) -> u64;
    /// This is actually a design hack, because when we verify the signature we
    /// can't know Big Brother's ID type (Sr25519 vs Ed25519)
    fn update_big_brother(&mut self, big_brother: nagara_identities::public::PublicKey);
    /// Decree's signature verification, don't override this unless for testing
    /// purpose
    fn verify_big_brother(&mut self) -> crate::Result<()> {
        let mut big_brother = *self.big_brother();
        big_brother.verify(self.big_brother_signature(), self.object_hash().as_bytes())?;
        self.update_big_brother(big_brother);

        Ok(())
    }
}

pub trait IBufferFormat: Sized {
    /// Deserialize the type from raw bytes
    fn from_bytes(source: &[u8]) -> crate::Result<Self>;
    /// Serialize the type into a buffer
    fn into_bytes(&self, destination: &mut [u8]) -> crate::Result<()>;
}

pub trait IEncryptedEnvelope<D: IAttestableDecree>: IBufferFormat + Sized {
    /// Maximum size of the content, don't override this to more than 256 MiB
    const LEN_MAX_CONTENT: usize = 256 * 1024 * 1024;
    /// Key derivation function, must be consistent across implementations
    fn derive_cipher_key(source: &[u8]) -> crate::Result<morus::Key>;
    /// Pointer to encrypted content
    fn encrypted_content(&self) -> &[u8];
    /// Hash of the encrypted content
    fn hash_encrypted(&self) -> &blake3::Hash;
    /// Hash of the decrypted/plain content
    fn hash_plain(&self) -> &blake3::Hash;
    /// Encryption Nonce
    fn nonce(&self) -> &morus::Nonce;
    /// Receiver public key
    fn receiver(&self) -> &nagara_identities::public::PublicKey;
    /// Sender public key
    fn sender(&self) -> &nagara_identities::public::PublicKey;
    /// Encryption Tag
    fn tag(&self) -> &morus::Tag;
    /// Unchecked constructor
    fn new_unchecked(
        sender: nagara_identities::public::PublicKey,
        receiver: nagara_identities::public::PublicKey,
        hash_encrypted: blake3::Hash,
        hash_plain: blake3::Hash,
        nonce: morus::Nonce,
        tag: morus::Tag,
        encrypted_content: alloc::vec::Vec<u8>,
    ) -> Self;
    /// Storing encryption, from user to a Cooperative Node (Ksatria) that
    /// equipped with a Sentinel (Keris).
    fn new_with_decree(
        decree: &mut D,
        file_sk: nagara_identities::private::PrivateKey,
        sentinel_id: nagara_identities::public::PublicKey,
        mut content: alloc::vec::Vec<u8>,
    ) -> crate::Result<Self> {
        crate::ensure!(content.len() <= Self::LEN_MAX_CONTENT, crate::Error::ObjectSizeExceeded);
        decree.verify_big_brother()?;
        crate::ensure!(sentinel_id.is_edward(), crate::Error::SchnorrkelIsNotSupported);
        crate::ensure!(decree.sentinel().eq(&sentinel_id), crate::Error::InvalidDecreeSentinel);
        let file_ci = nagara_identities::CryptographicIdentity::from(file_sk);
        let sentinel_ci = nagara_identities::CryptographicIdentity::from(sentinel_id);
        let object_id = file_ci.try_get_public_ed25519().unwrap();
        crate::ensure!(decree.object_id().eq(&object_id), crate::Error::DecreeObjectMismatch);
        let hash_plain = blake3::hash(&content);
        crate::ensure!(hash_plain.eq(decree.object_hash()), crate::Error::DecreeObjectMismatch);
        let shared_key = file_ci.try_get_shared_secret(&sentinel_ci)?;
        let key = Self::derive_cipher_key(&shared_key)?;
        let mut nonce = morus::Nonce::default();
        getrandom::getrandom(&mut nonce)?;
        let encryptor = morus::Morus::new(&nonce, &key);
        let tag = encryptor.encrypt_in_place(&mut content, &[]);
        let sender = object_id;
        let receiver = sentinel_ci.try_get_public_ed25519().unwrap();
        let hash_encrypted = blake3::hash(&content);
        let self_instance = Self::new_unchecked(sender, receiver, hash_encrypted, hash_plain, nonce, tag, content);

        crate::Result::Ok(self_instance)
    }
    /// Decrypt the envelope with given ticket, don't override this unless we
    /// don't use Morus1280-128
    fn permissioned_decrypt(
        self,
        beneficiary_sk: nagara_identities::private::PrivateKey,
        ticket: &crate::DecryptionTicket,
        destination: &mut [u8],
    ) -> crate::Result<()> {
        let encrypted_slice = self.encrypted_content();
        crate::ensure!(
            destination.len() == encrypted_slice.len(),
            crate::Error::InvalidBufferLength
        );
        let receiver_ci = nagara_identities::CryptographicIdentity::from(beneficiary_sk);
        let sender_ci = nagara_identities::CryptographicIdentity::from(*self.sender());
        let shared_key = receiver_ci.try_get_shared_secret(&sender_ci)?;
        let key = Self::derive_cipher_key(&shared_key)?;
        let decryptor = morus::Morus::new(self.nonce(), &key);
        destination.copy_from_slice(encrypted_slice);
        decryptor.decrypt_in_place(destination, self.tag(), ticket)?;

        crate::Result::Ok(())
    }
    /// ** This is a reference implementation for non-enclaved Sentinel.
    /// Enclaved Sentinel has its own `no_std` & `no_alloc` implementation **
    ///
    /// Ensure storing decree is valid, by decrypting it
    #[cfg(feature = "reference-sentinel")]
    fn sentinel_ensure_valid_storing_decree(
        &self,
        decree: &mut D,
        sentinel_sk: nagara_identities::private::PrivateKey,
    ) -> crate::Result<alloc::vec::Vec<u8>> {
        decree.verify_big_brother()?;
        crate::ensure!(decree.object_id().eq(self.sender()), crate::Error::DecreeObjectMismatch);
        crate::ensure!(self.sender().is_edward(), crate::Error::SchnorrkelIsNotSupported);
        let file_ci = nagara_identities::CryptographicIdentity::from(*self.sender());
        let sentinel_ci = nagara_identities::CryptographicIdentity::from(sentinel_sk);
        let sentinel_pk = sentinel_ci.try_get_public_ed25519().unwrap();
        crate::ensure!(sentinel_pk.eq(decree.sentinel()), crate::Error::InvalidDecreeSentinel);
        let shared_key = sentinel_ci.try_get_shared_secret(&file_ci)?;
        let key = Self::derive_cipher_key(&shared_key)?;
        let decryptor = morus::Morus::new(self.nonce(), &key);
        let decrypted_vec = decryptor.decrypt(self.encrypted_content(), self.tag(), &[])?;
        let hash_decrypted = blake3::hash(&decrypted_vec);
        crate::ensure!(
            hash_decrypted.eq(decree.object_hash()),
            crate::Error::DecreeObjectMismatch
        );

        crate::Result::Ok(decrypted_vec)
    }
    /// ** This is a reference implementation for non-enclaved Sentinel.
    /// Enclaved Sentinel has its own `no_std` & `no_alloc` implementation **
    ///
    /// Recontruct this into serviceable
    #[cfg(feature = "reference-sentinel")]
    fn sentinel_reconstruct(
        self,
        decree: &mut D,
        sentinel_sk: nagara_identities::private::PrivateKey,
    ) -> crate::Result<(Self, crate::DecryptionTicket)> {
        let mut decrypted_vec = self.sentinel_ensure_valid_storing_decree(decree, sentinel_sk.clone())?;
        let beneficiary_ci = nagara_identities::CryptographicIdentity::from(*decree.beneficiary());
        let sentinel_ci = nagara_identities::CryptographicIdentity::from(sentinel_sk);
        crate::ensure!(beneficiary_ci.is_edward(), crate::Error::SchnorrkelIsNotSupported);
        let mut nonce = morus::Nonce::default();
        let mut decryption_ticket = crate::DecryptionTicket::default();
        getrandom::getrandom(&mut nonce)?;
        getrandom::getrandom(&mut decryption_ticket)?;
        let shared_key = sentinel_ci.try_get_shared_secret(&beneficiary_ci)?;
        let key = Self::derive_cipher_key(&shared_key)?;
        let encryptor = morus::Morus::new(&nonce, &key);
        let tag = encryptor.encrypt_in_place(&mut decrypted_vec, &decryption_ticket);
        let encrypted_content = decrypted_vec;
        let sender = sentinel_ci.try_get_public_ed25519().unwrap();
        let receiver = beneficiary_ci.try_get_public_ed25519().unwrap();
        let hash_encrypted = blake3::hash(&encrypted_content);
        let hash_plain = *decree.object_hash();
        let self_instance = Self::new_unchecked(
            sender,
            receiver,
            hash_encrypted,
            hash_plain,
            nonce,
            tag,
            encrypted_content,
        );

        crate::Result::Ok((self_instance, decryption_ticket))
    }
}
