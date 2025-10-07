use alloc::vec::Vec;
use rand::{CryptoRng, RngCore};

use super::{
    error::IntegratedEncryptionSchemeError,
    message::{CryptoAlgorithm, SealedMessage},
};

/// Trait for sealing (encrypting) messages
pub trait SealingKeyTrait {
    fn seal<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, IntegratedEncryptionSchemeError>;

    fn algorithm(&self) -> CryptoAlgorithm;
}

/// Trait for unsealing (decrypting) messages
pub trait UnsealingKeyTrait {
    fn unseal(
        &self,
        sealed_message: SealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IntegratedEncryptionSchemeError>;

    fn algorithm(&self) -> CryptoAlgorithm;
    fn algorithm_name(&self) -> &'static str;
}

/// Trait for ephemeral public keys
pub trait EphemeralKeyTrait {
    fn algorithm(&self) -> CryptoAlgorithm;
    fn to_bytes(&self) -> Vec<u8>;
}

