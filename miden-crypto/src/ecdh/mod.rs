//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementations.

use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, RngCore};
use winter_utils::{Deserializable, Serializable};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod k256;
pub mod x25519;

// KEY AGREEMENT TRAITS
// ================================================================================================

/// Key agreement scheme implemented directly on public key structs
pub trait KeyAgreementScheme {
    type EphemeralSecretKey: ZeroizeOnDrop;
    type EphemeralPublicKey: Serializable + Deserializable;
    type SecretKey;
    type SharedSecret: AsRef<[u8]> + Zeroize + ZeroizeOnDrop;

    /// Generate an ephemeral keypair for key agreement with this public key's curve
    fn generate_ephemeral_keypair<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> (Self::EphemeralSecretKey, Self::EphemeralPublicKey);

    /// Perform key exchange between an ephemeral secret key and this public key
    fn exchange_ephemeral_static(
        &self,
        ephemeral_sk: Self::EphemeralSecretKey,
    ) -> Result<Self::SharedSecret, KeyAgreementError>;

    /// Perform key exchange between a static secret key and an ephemeral public key
    fn exchange_static_ephemeral(
        &self,
        static_sk: &Self::SecretKey,
        ephemeral_pk: &Self::EphemeralPublicKey,
    ) -> Result<Self::SharedSecret, KeyAgreementError>;

    /// Extract key material from a shared secret
    fn extract_key_material(
        &self,
        shared_secret: &Self::SharedSecret,
        length: usize,
    ) -> Result<Vec<u8>, KeyAgreementError>;

    /// Create a dummy public key for use with secret key operations
    /// This enables secure IES operations by allowing trait-based access to secret key methods
    fn dummy_public_key_for_secret_key(secret_key: &Self::SecretKey) -> Self;
}

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug)]
pub enum KeyAgreementError {
    FailedKeyAgreement,
    PublicKeyDeserializationFailed,
    HkdfExpansionFailed,
}

impl fmt::Display for KeyAgreementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAgreementError::FailedKeyAgreement => {
                write!(f, "key agreement failed")
            },
            KeyAgreementError::PublicKeyDeserializationFailed => {
                write!(f, "deserialization of public key failed")
            },
            KeyAgreementError::HkdfExpansionFailed => {
                write!(f, "hkdf expansion failed")
            },
        }
    }
}

impl core::error::Error for KeyAgreementError {}
