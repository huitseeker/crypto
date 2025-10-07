use alloc::vec::Vec;
use core::convert::TryFrom;

use super::{crypto_box::RawSealedMessage, error::IntegratedEncryptionSchemeError};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Supported algorithms for IES
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IesAlgorithm {
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

/// A sealed message containing encrypted data and algorithm information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessage {
    /// Algorithm identifier for the encryption scheme used
    pub(crate) algorithm: IesAlgorithm,
    /// Ephemeral public key bytes (used for key agreement)
    pub(crate) ephemeral_public_key: Vec<u8>,
    /// Encrypted ciphertext with authentication tag and nonce
    pub(crate) ciphertext: Vec<u8>,
}

impl SealedMessage {
    /// Create a new SealedMessage from components
    pub fn new(
        algorithm: IesAlgorithm,
        ephemeral_public_key: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            algorithm,
            ephemeral_public_key,
            ciphertext,
        }
    }

    /// Get the algorithm used to create this sealed message
    pub fn algorithm(&self) -> IesAlgorithm {
        self.algorithm
    }

    /// Get the algorithm name used to create this sealed message
    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm.name()
    }

    /// Get the ephemeral public key bytes
    pub fn ephemeral_public_key(&self) -> &[u8] {
        &self.ephemeral_public_key
    }

    /// Get the ciphertext
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Convert to RawSealedMessage for internal crypto operations
    pub(crate) fn to_raw(&self) -> RawSealedMessage {
        RawSealedMessage {
            ephemeral_public_key: self.ephemeral_public_key.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// Convert from RawSealedMessage with algorithm specification
impl From<(IesAlgorithm, RawSealedMessage)> for SealedMessage {
    fn from((algorithm, raw): (IesAlgorithm, RawSealedMessage)) -> Self {
        Self {
            algorithm,
            ephemeral_public_key: raw.ephemeral_public_key,
            ciphertext: raw.ciphertext,
        }
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SealedMessage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.algorithm as u8);
        target.write_usize(self.ephemeral_public_key.len());
        target.write_bytes(&self.ephemeral_public_key);
        target.write_usize(self.ciphertext.len());
        target.write_bytes(&self.ciphertext);
    }
}

impl Deserializable for SealedMessage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let algorithm = match IesAlgorithm::try_from(source.read_u8()?) {
            Ok(a) => a,
            Err(_) => {
                return Err(DeserializationError::InvalidValue("Unsupported algorithm".into()));
            },
        };

        let eph_key_len = source.read_usize()?;
        let ephemeral_public_key = source.read_vec(eph_key_len)?;

        let ciphertext_len = source.read_usize()?;
        let ciphertext = source.read_vec(ciphertext_len)?;

        Ok(Self {
            algorithm,
            ephemeral_public_key,
            ciphertext,
        })
    }
}
