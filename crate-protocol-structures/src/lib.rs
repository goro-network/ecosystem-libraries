#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//#![deny(warnings)]

#[cfg(all(feature = "opt-aarch64", feature = "wasm32"))]
compile_error!("Feature \"opt-aarch64\" can't be combined with \"wasm32\".");

extern crate alloc;

pub use concrete::*;
pub use errors::*;
pub use traits::*;

pub type DecryptionTicket = [u8; 8]; // can be stored as u64 (little endian)
pub type Result<T> = core::result::Result<T, crate::errors::Error>;

mod concrete;
mod errors;
mod traits;

#[cfg(all(test, feature = "reference-sentinel"))]
mod tests {
    use super::*;
    use blake3::hash;
    use getrandom::getrandom;
    use nagara_identities::CryptographicIdentity;

    fn compose_decree(
        object_ci: &CryptographicIdentity,
        sentinel_ci: &CryptographicIdentity,
        beneficiary_ci: &CryptographicIdentity,
        object_data_plain: &[u8],
    ) -> Decree {
        let big_brother_ci = CryptographicIdentity::generate();
        let object_hash = hash(object_data_plain);
        let big_brother_signature = big_brother_ci.try_sign(true, object_hash.as_bytes()).unwrap();
        let sequence = 0;
        let sentinel = sentinel_ci.try_get_public_ed25519().unwrap();
        let big_brother = big_brother_ci.try_get_public_sr25519().unwrap();
        let beneficiary = beneficiary_ci.try_get_public_ed25519().unwrap();
        let object_id = object_ci.try_get_public_ed25519().unwrap();

        Decree {
            sequence,
            sentinel,
            big_brother,
            big_brother_signature,
            beneficiary,
            object_hash,
            object_id,
        }
    }

    #[test]
    fn storing_is_valid() {
        // compose - store_pda
        let beneficiary_ci = CryptographicIdentity::generate();
        let file_ci = CryptographicIdentity::generate();
        let sentinel_ci = CryptographicIdentity::generate();
        let mut content = vec![0; <PermissionedData as IEncryptedEnvelope<Decree>>::LEN_MAX_CONTENT];
        getrandom(&mut content).unwrap();
        let mut decree = compose_decree(&file_ci, &sentinel_ci, &beneficiary_ci, &content);
        let store_pda = PermissionedData::new_with_decree(
            &mut decree,
            file_ci.try_get_private_key().unwrap(),
            sentinel_ci.try_get_public_ed25519().unwrap(),
            content.clone(),
        )
        .unwrap();
        // verify - store_pda
        let decrypted_content = store_pda
            .sentinel_ensure_valid_storing_decree(&mut decree, sentinel_ci.try_get_private_key().unwrap())
            .unwrap();
        // assertion(s)
        assert_eq!(content, decrypted_content);
    }

    #[test]
    fn service_is_valid() {
        // compose - store_pda
        let beneficiary_ci = CryptographicIdentity::generate();
        let file_ci = CryptographicIdentity::generate();
        let sentinel_ci = CryptographicIdentity::generate();
        let mut content = vec![0; <PermissionedData as IEncryptedEnvelope<Decree>>::LEN_MAX_CONTENT];
        getrandom(&mut content).unwrap();
        let mut decree = compose_decree(&file_ci, &sentinel_ci, &beneficiary_ci, &content);
        let store_pda = PermissionedData::new_with_decree(
            &mut decree,
            file_ci.try_get_private_key().unwrap(),
            sentinel_ci.try_get_public_ed25519().unwrap(),
            content.clone(),
        )
        .unwrap();
        // reconstruct - service_pda
        let mut service_decree = decree.clone(); // reuse decree only for test
        let (service_pda, decryption_ticket) = store_pda
            .sentinel_reconstruct(&mut service_decree, sentinel_ci.try_get_private_key().unwrap())
            .unwrap();
        // decrypt & assert
        let mut decrypted_content = vec![0; content.len()];
        service_pda
            .permissioned_decrypt(
                beneficiary_ci.try_get_private_key().unwrap(),
                &decryption_ticket,
                &mut decrypted_content,
            )
            .unwrap();
        assert_eq!(decrypted_content, content);
    }
}
