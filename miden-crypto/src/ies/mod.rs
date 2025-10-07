//! Integrated Encryption Scheme (IES) module.
//!
//! This module provides high-level authenticated encryption built from combining elliptic-curve
//! Diffie–Hellman (ECDH) for key agreement with an authenticated encryption with associated data
//! scheme for message encryption.
//!
//! The implementation uses direct trait implementations on key structs for optimal performance
//! and proper cryptographic security.
//!
//! The implementation is split across three submodules:
//! - [`crypto_box`] - Core `CryptoBox` primitive & raw message format
//! - [`message`] - Sealed message format and algorithm identifiers
//! - [`error`] - Error types for IES operations

mod crypto_box;
mod error;
mod message;

#[cfg(test)]
mod tests;

pub use error::IntegratedEncryptionSchemeError;
pub use message::SealedMessage;
