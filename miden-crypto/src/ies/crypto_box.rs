use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::error::IntegratedEncryptionSchemeError;
use crate::{
    Felt,
    aead::AeadScheme,
    ecdh::KeyAgreementScheme,
    utils::{Deserializable, Serializable},
};

/// Raw sealed message representation
#[derive(Debug)]
pub(crate) struct RawSealedMessage {
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl CryptoBox {
    // BYTE-SPECIFIC METHODS
    // ================================================================================================

    /// Seal bytes with associated data
    pub(crate) fn seal_bytes_with_associated_data<
        KA: KeyAgreementScheme,
        AE: AeadScheme,
        R: CryptoRng + RngCore,
    >(
        rng: &mut R,
        recipient_public_key: &KA,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RawSealedMessage, IntegratedEncryptionSchemeError> {
        let (ephemeral_private, ephemeral_public) =
            recipient_public_key.generate_ephemeral_keypair(rng);

        let shared_secret = Zeroizing::new(
            recipient_public_key
                .exchange_ephemeral_static(ephemeral_private)
                .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?,
        );

        let encryption_key_bytes = Zeroizing::new(
            recipient_public_key
                .extract_key_material(&shared_secret, AE::KEY_SIZE)
                .map_err(|_| IntegratedEncryptionSchemeError::FailedExtractKeyMaterial)?,
        );

        let encryption_key = Zeroizing::new(
            AE::key_from_bytes(&encryption_key_bytes)
                .map_err(|_| IntegratedEncryptionSchemeError::EncryptionKeyCreationFailed)?,
        );

        let ciphertext = AE::encrypt_bytes(&encryption_key, rng, plaintext, associated_data)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionFailed)?;

        Ok(RawSealedMessage {
            ciphertext,
            ephemeral_public_key: ephemeral_public.to_bytes(),
        })
    }

    /// Unseal bytes with associated data
    pub(crate) fn unseal_bytes_with_associated_data<KA: KeyAgreementScheme, AE: AeadScheme>(
        recipient_secret_key: &KA::SecretKey,
        sealed_message: &RawSealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError> {
        let ephemeral_public = KA::EphemeralPublicKey::read_from_bytes(
            &sealed_message.ephemeral_public_key,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed)?;

        let dummy_public_key = KA::dummy_public_key_for_secret_key(recipient_secret_key);

        let shared_secret = Zeroizing::new(
            dummy_public_key
                .exchange_static_ephemeral(recipient_secret_key, &ephemeral_public)
                .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?,
        );

        let decryption_key_bytes = Zeroizing::new(
            dummy_public_key
                .extract_key_material(&shared_secret, AE::KEY_SIZE)
                .map_err(|_| IntegratedEncryptionSchemeError::FailedExtractKeyMaterial)?,
        );

        let decryption_key = Zeroizing::new(
            AE::key_from_bytes(&decryption_key_bytes)
                .map_err(|_| IntegratedEncryptionSchemeError::DecryptionFailed)?,
        );

        let result = AE::decrypt_bytes_with_associated_data(
            &decryption_key,
            &sealed_message.ciphertext,
            associated_data,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::DecryptionFailed)?;

        Ok(result)
    }

    // FELT-SPECIFIC METHODS
    // ================================================================================================

    /// Seal field elements with associated data
    pub(crate) fn seal_elements_with_associated_data<
        KA: KeyAgreementScheme,
        AE: AeadScheme,
        R: CryptoRng + RngCore,
    >(
        rng: &mut R,
        recipient_public_key: &KA,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<RawSealedMessage, IntegratedEncryptionSchemeError> {
        let (ephemeral_private, ephemeral_public) =
            recipient_public_key.generate_ephemeral_keypair(rng);

        let shared_secret = Zeroizing::new(
            recipient_public_key
                .exchange_ephemeral_static(ephemeral_private)
                .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?,
        );

        let encryption_key_bytes = Zeroizing::new(
            recipient_public_key
                .extract_key_material(&shared_secret, AE::KEY_SIZE)
                .map_err(|_| IntegratedEncryptionSchemeError::FailedExtractKeyMaterial)?,
        );

        let encryption_key = Zeroizing::new(
            AE::key_from_bytes(&encryption_key_bytes)
                .map_err(|_| IntegratedEncryptionSchemeError::EncryptionKeyCreationFailed)?,
        );

        let ciphertext = AE::encrypt_elements(&encryption_key, rng, plaintext, associated_data)
            .map_err(|_| IntegratedEncryptionSchemeError::EncryptionFailed)?;

        Ok(RawSealedMessage {
            ciphertext,
            ephemeral_public_key: ephemeral_public.to_bytes(),
        })
    }

    /// Unseal field elements with associated data
    pub(crate) fn unseal_elements_with_associated_data<KA: KeyAgreementScheme, AE: AeadScheme>(
        recipient_secret_key: &KA::SecretKey,
        sealed_message: &RawSealedMessage,
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, IntegratedEncryptionSchemeError> {
        let ephemeral_public = KA::EphemeralPublicKey::read_from_bytes(
            &sealed_message.ephemeral_public_key,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed)?;

        // PROPER IES: Create dummy public key to access trait methods
        let dummy_public_key = KA::dummy_public_key_for_secret_key(recipient_secret_key);

        // PROPER IES: Compute shared secret from ECDH (should match sender's computation)
        let shared_secret = Zeroizing::new(
            dummy_public_key
                .exchange_static_ephemeral(recipient_secret_key, &ephemeral_public)
                .map_err(|_| IntegratedEncryptionSchemeError::KeyAgreementFailed)?,
        );

        // PROPER IES: Derive decryption key from shared secret using KDF
        let decryption_key_bytes = Zeroizing::new(
            dummy_public_key
                .extract_key_material(&shared_secret, AE::KEY_SIZE)
                .map_err(|_| IntegratedEncryptionSchemeError::FailedExtractKeyMaterial)?,
        );

        // PROPER IES: Create AEAD key from derived bytes
        let decryption_key = Zeroizing::new(
            AE::key_from_bytes(&decryption_key_bytes)
                .map_err(|_| IntegratedEncryptionSchemeError::DecryptionFailed)?,
        );

        // PROPER IES: Decrypt using derived key (only works with correct recipient's secret key)
        let result = AE::decrypt_elements_with_associated_data(
            &decryption_key,
            &sealed_message.ciphertext,
            associated_data,
        )
        .map_err(|_| IntegratedEncryptionSchemeError::DecryptionFailed)?;

        Ok(result)
    }
}

/// CryptoBox for namespacing
pub(crate) struct CryptoBox;
