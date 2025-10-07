


// Note: This module needs to be refactored to use the new direct trait implementation pattern
// TODO: Replace the enum-based approach with direct trait usage on key structs

// HELPER MACROS
// ================================================================================================

/// Generates seal_with_associated_data method implementation
macro_rules! impl_seal_with_associated_data {
    ($($variant:path => $crypto_box:ty, $key_agreement:ty, $ephemeral_variant:path;)*) => {
        /// Seal (encrypt and authenticate) data for this recipient given some associated data
        pub fn seal_with_associated_data<R: CryptoRng + RngCore>(
            &self,
            rng: &mut R,
            plaintext: &[u8],
            associated_data: &[u8],
        ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
            match self {
                $(
                    $variant(key) => {
                        let raw = <$crypto_box>::seal_with_associated_data(
                            rng,
                            key,
                            plaintext,
                            associated_data,
                        )?;

                        let ephemeral = <$key_agreement as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                            &raw.ephemeral_public_key,
                        )
                        .map_err(|_| {
                            IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                        })?;

                        Ok(SealedMessage {
                            ephemeral_key: $ephemeral_variant(ephemeral),
                            ciphertext: raw.ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Generates seal_elements_with_associated_data method implementation
macro_rules! impl_seal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty, $key_agreement:ty, $ephemeral_variant:path;)*) => {
        /// Seal field elements with associated data for this recipient
        pub fn seal_elements_with_associated_data<R: CryptoRng + RngCore>(
            &self,
            rng: &mut R,
            plaintext: &[Felt],
            associated_data: &[Felt],
        ) -> Result<SealedMessage, IntegratedEncryptionSchemeError> {
            match self {
                $(
                    $variant(key) => {
                        let raw = <$crypto_box>::seal_elements_with_associated_data(
                            rng,
                            key,
                            plaintext,
                            associated_data,
                        )?;

                        let ephemeral = <$key_agreement as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes(
                            &raw.ephemeral_public_key,
                        )
                        .map_err(|_| {
                            IntegratedEncryptionSchemeError::EphemeralPublicKeyDeserializationFailed
                        })?;

                        Ok(SealedMessage {
                            ephemeral_key: $ephemeral_variant(ephemeral),
                            ciphertext: raw.ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Generates unseal_with_associated_data method implementation
macro_rules! impl_unseal_with_associated_data {
    ($($variant:path => $crypto_box:ty;)*) => {
        /// Unseal a sealed message given its associated data
        pub fn unseal_with_associated_data(
            &self,
            sealed_message: SealedMessage,
            associated_data: &[u8],
        ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError> {
            // Check algorithm compatibility using constant-time comparison
            let self_algo = self.algorithm() as u8;
            let msg_algo = sealed_message.ephemeral_key.algorithm() as u8;

            let compatible = self_algo == msg_algo;
            if !compatible {
                return Err(IntegratedEncryptionSchemeError::AlgorithmMismatch);
            }

            // Destructure and serialize the ephemeral key
            let SealedMessage { ephemeral_key, ciphertext } = sealed_message;
            let raw_sealed = RawSealedMessage {
                ephemeral_public_key: ephemeral_key.to_bytes(),
                ciphertext,
            };

            match self {
                $(
                    $variant(key) => {
                        <$crypto_box>::unseal_with_associated_data(key, &raw_sealed, associated_data)
                    }
                )*
            }
        }
    };
}

/// Generates unseal_elements_with_associated_data method implementation
macro_rules! impl_unseal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty;)*) => {
        /// Unseal field elements from a sealed message with associated data
        pub fn unseal_elements_with_associated_data(
            &self,
            sealed_message: SealedMessage,
            associated_data: &[Felt],
        ) -> Result<Vec<Felt>, IntegratedEncryptionSchemeError> {
            match self {
                $(
                    $variant(key) => {
                        // Check algorithm compatibility
                        let self_algo = self.algorithm() as u8;
                        let msg_algo = sealed_message.ephemeral_key.algorithm() as u8;

                        let compatible = self_algo == msg_algo;
                        if !compatible {
                            return Err(IntegratedEncryptionSchemeError::AlgorithmMismatch);
                        }

                        // Destructure and serialize the ephemeral key
                        let SealedMessage { ephemeral_key, ciphertext } = sealed_message;
                        let raw_sealed = RawSealedMessage {
                            ephemeral_public_key: ephemeral_key.to_bytes(),
                            ciphertext,
                        };

                        <$crypto_box>::unseal_elements_with_associated_data(key, &raw_sealed, associated_data)
                    }
                )*
            }
        }
    };
}

// STRUCTS AND IMPLEMENTATIONS
// ================================================================================================

// TODO: Refactor SealingKey to use direct trait implementations
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub enum SealingKey {
//     K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::PublicKey),
//     X25519XChaCha20Poly1305(crate::dsa::eddsa_25519::PublicKey),
//     K256AeadRpo(crate::dsa::ecdsa_k256_keccak::PublicKey),
//     X25519AeadRpo(crate::dsa::eddsa_25519::PublicKey),
// }

// TODO: Refactor UnsealingKey to use direct trait implementations
// pub enum UnsealingKey {
//     K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::SecretKey),
//     X25519XChaCha20Poly1305(crate::dsa::eddsa_25519::SecretKey),
//     K256AeadRpo(crate::dsa::ecdsa_k256_keccak::SecretKey),
//     X25519AeadRpo(crate::dsa::eddsa_25519::SecretKey),
// }

// TODO: Refactor EphemeralPublicKey to use direct trait implementations
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub(crate) enum EphemeralPublicKey {
//     K256XChaCha20Poly1305(crate::ecdh::k256::EphemeralPublicKey),
//     X25519XChaCha20Poly1305(crate::ecdh::x25519::EphemeralPublicKey),
//     K256AeadRpo(crate::ecdh::k256::EphemeralPublicKey),
//     X25519AeadRpo(crate::ecdh::x25519::EphemeralPublicKey),
// }
