use core::convert::TryFrom;

// TODO: Re-enable when refactored to use direct trait implementations
// use super::{error::IntegratedEncryptionSchemeError, keys::EphemeralPublicKey};
use super::error::IntegratedEncryptionSchemeError;

/// Supported algorithms for IES
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum IesAlgorithm {
    K256XChaCha20Poly1305 = 0,
    X25519XChaCha20Poly1305 = 1,
    K256AeadRpo = 2,
    X25519AeadRpo = 3,
}

impl TryFrom<u8> for IesAlgorithm {
    type Error = IntegratedEncryptionSchemeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IesAlgorithm::K256XChaCha20Poly1305),
            1 => Ok(IesAlgorithm::X25519XChaCha20Poly1305),
            2 => Ok(IesAlgorithm::K256AeadRpo),
            3 => Ok(IesAlgorithm::X25519AeadRpo),
            _ => Err(IntegratedEncryptionSchemeError::UnsupportedAlgorithm),
        }
    }
}

impl From<IesAlgorithm> for u8 {
    fn from(algo: IesAlgorithm) -> Self {
        algo as u8
    }
}

impl core::fmt::Display for IesAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl IesAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            IesAlgorithm::K256XChaCha20Poly1305 => "K256+XChaCha20-Poly1305",
            IesAlgorithm::X25519XChaCha20Poly1305 => "X25519+XChaCha20-Poly1305",
            IesAlgorithm::K256AeadRpo => "K256+AeadRpo",
            IesAlgorithm::X25519AeadRpo => "X25519+AeadRpo",
        }
    }
}

// TODO: Refactor SealedMessage to use direct trait implementations
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct SealedMessage {
//     /// Ephemeral public key (determines algorithm and provides key material)
//     pub(crate) ephemeral_key: EphemeralPublicKey,
//     /// Encrypted ciphertext with authentication tag and nonce
//     pub(crate) ciphertext: Vec<u8>,
// }

// TODO: Re-enable serialization when refactored to use direct trait implementations
// impl Serializable for SealedMessage { ... }
// impl Deserializable for SealedMessage { ... }
