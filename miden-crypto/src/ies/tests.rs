use alloc::vec::Vec;

use crate::{
    aead::{aead_rpo::SecretKey as AeadRpoKey, xchacha::SecretKey as XChaChaKey},
    dsa::{
        ecdsa_k256_keccak::SecretKey as K256SecretKey, eddsa_25519::SecretKey as X25519SecretKey,
    },
    ies::crypto_box::CryptoBox,
    utils::Deserializable,
};

// Helper function to create a sealed message using proper IES design
fn seal_with_new_api<KA, AE, R>(
    rng: &mut R,
    recipient_public_key: &KA,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<crate::ies::crypto_box::RawSealedMessage, crate::ies::IntegratedEncryptionSchemeError>
where
    KA: crate::ecdh::KeyAgreementScheme,
    AE: crate::aead::AeadScheme,
    R: rand::CryptoRng + rand::RngCore,
{
    CryptoBox::seal_bytes_with_associated_data::<KA, AE, R>(
        rng,
        recipient_public_key,
        plaintext,
        associated_data,
    )
}

// Helper function to unseal a message using proper IES design
fn unseal_with_new_api<KA, AE>(
    recipient_secret_key: &KA::SecretKey,
    sealed_message: &crate::ies::crypto_box::RawSealedMessage,
    associated_data: &[u8],
) -> Result<Vec<u8>, crate::ies::IntegratedEncryptionSchemeError>
where
    KA: crate::ecdh::KeyAgreementScheme,
    AE: crate::aead::AeadScheme,
{
    CryptoBox::unseal_bytes_with_associated_data::<KA, AE>(
        recipient_secret_key,
        sealed_message,
        associated_data,
    )
}

// Basic unit tests adapted to the new direct trait approach
#[test]
fn test_k256_xchacha_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = b"roundtrip";
    let ad = b"ctx";

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Seal using proper IES design
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, plaintext, ad).unwrap();

    // Unseal using proper IES design
    let decrypted = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        ad,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_k256_xchacha_bytes_with_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"test message with associated data";
    let associated_data = b"additional context for authentication";

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Seal with associated data
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, plaintext, associated_data)
            .unwrap();

    // Unseal with same associated data should succeed
    let decrypted = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        associated_data,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);

    // Unseal with different associated data should fail
    let wrong_ad = b"wrong associated data";
    let result = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        wrong_ad,
    );
    assert!(result.is_err());
}

#[test]
fn test_x25519_xchacha_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = b"roundtrip-x25519";
    let ad = b"ctx-x25519";

    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, plaintext, ad).unwrap();
    let decrypted = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        ad,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_x25519_xchacha_bytes_with_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"x25519 message with associated data";
    let associated_data = b"x25519 additional context";

    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Seal with associated data
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, plaintext, associated_data)
            .unwrap();

    // Unseal with same associated data should succeed
    let decrypted = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        associated_data,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);

    // Unseal with different associated data should fail
    let wrong_ad = b"x25519 wrong associated data";
    let result = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        wrong_ad,
    );
    assert!(result.is_err());
}

#[test]
fn test_x25519_aead_rpo_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = b"roundtrip-rpo";
    let ad = b"ctx-rpo";

    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed =
        seal_with_new_api::<_, AeadRpoKey, _>(&mut rng, &public_key, plaintext, ad).unwrap();
    let decrypted = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, AeadRpoKey>(
        &secret_key,
        &sealed,
        ad,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_k256_aead_rpo_bytes_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = b"k256 rpo roundtrip test";
    let ad = b"k256-rpo-ctx";

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed =
        seal_with_new_api::<_, AeadRpoKey, _>(&mut rng, &public_key, plaintext, ad).unwrap();
    let decrypted = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, AeadRpoKey>(
        &secret_key,
        &sealed,
        ad,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_k256_aead_rpo_bytes_with_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"k256 rpo message with associated data";
    let associated_data = b"k256 rpo additional context";

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Seal with associated data
    let sealed =
        seal_with_new_api::<_, AeadRpoKey, _>(&mut rng, &public_key, plaintext, associated_data)
            .unwrap();

    // Unseal with same associated data should succeed
    let decrypted = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, AeadRpoKey>(
        &secret_key,
        &sealed,
        associated_data,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);

    // Unseal with different associated data should fail
    let wrong_ad = b"k256 rpo wrong associated data";
    let result = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, AeadRpoKey>(
        &secret_key,
        &sealed,
        wrong_ad,
    );
    assert!(result.is_err());
}

#[test]
fn test_x25519_aead_rpo_bytes_with_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"x25519 rpo message with associated data";
    let associated_data = b"x25519 rpo additional context";

    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Seal with associated data
    let sealed =
        seal_with_new_api::<_, AeadRpoKey, _>(&mut rng, &public_key, plaintext, associated_data)
            .unwrap();

    // Unseal with same associated data should succeed
    let decrypted = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, AeadRpoKey>(
        &secret_key,
        &sealed,
        associated_data,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);

    // Unseal with different associated data should fail
    let wrong_ad = b"x25519 rpo wrong associated data";
    let result = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, AeadRpoKey>(
        &secret_key,
        &sealed,
        wrong_ad,
    );
    assert!(result.is_err());
}

#[test]
fn test_invalid_associated_data() {
    let mut rng = rand::rng();
    let plaintext = b"with ad";
    let good_ad = b"good";
    let bad_ad = b"bad";

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, plaintext, good_ad).unwrap();
    let result = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        bad_ad,
    );

    assert!(result.is_err());
}

#[test]
fn test_field_element_sealing_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = vec![crate::Felt::new(1), crate::Felt::new(2), crate::Felt::new(3)];
    let associated_data = vec![crate::Felt::new(100), crate::Felt::new(200)];

    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed = CryptoBox::seal_elements_with_associated_data::<
        crate::dsa::eddsa_25519::PublicKey,
        AeadRpoKey,
        _,
    >(&mut rng, &public_key, &plaintext, &associated_data)
    .unwrap();

    let decrypted = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::eddsa_25519::PublicKey,
        AeadRpoKey,
    >(&secret_key, &sealed, &associated_data)
    .unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_k256_xchacha_elements_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = vec![
        crate::Felt::new(10),
        crate::Felt::new(20),
        crate::Felt::new(30),
        crate::Felt::new(40),
    ];
    let associated_data = vec![crate::Felt::new(100), crate::Felt::new(200)];

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed = CryptoBox::seal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        XChaChaKey,
        _,
    >(&mut rng, &public_key, &plaintext, &associated_data)
    .unwrap();

    let decrypted = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        XChaChaKey,
    >(&secret_key, &sealed, &associated_data)
    .unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_k256_xchacha_elements_with_associated_data() {
    let mut rng = rand::rng();
    let plaintext = vec![crate::Felt::new(15), crate::Felt::new(25), crate::Felt::new(35)];
    let associated_data = vec![crate::Felt::new(150), crate::Felt::new(250), crate::Felt::new(350)];

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Seal with associated data
    let sealed = CryptoBox::seal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        XChaChaKey,
        _,
    >(&mut rng, &public_key, &plaintext, &associated_data)
    .unwrap();

    // Unseal with same associated data should succeed
    let decrypted = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        XChaChaKey,
    >(&secret_key, &sealed, &associated_data)
    .unwrap();

    assert_eq!(plaintext, decrypted);

    // Unseal with different associated data should fail
    let wrong_ad = vec![crate::Felt::new(999), crate::Felt::new(888)];
    let result = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        XChaChaKey,
    >(&secret_key, &sealed, &wrong_ad);
    assert!(result.is_err());
}

#[test]
fn test_k256_aead_rpo_field_elements_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = vec![
        crate::Felt::new(50),
        crate::Felt::new(60),
        crate::Felt::new(70),
        crate::Felt::new(80),
    ];
    let associated_data = vec![crate::Felt::new(500), crate::Felt::new(600)];

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed = CryptoBox::seal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        AeadRpoKey,
        _,
    >(&mut rng, &public_key, &plaintext, &associated_data)
    .unwrap();

    let decrypted = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        AeadRpoKey,
    >(&secret_key, &sealed, &associated_data)
    .unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_k256_aead_rpo_field_elements_with_associated_data() {
    let mut rng = rand::rng();
    let plaintext = vec![crate::Felt::new(55), crate::Felt::new(65), crate::Felt::new(75)];
    let associated_data = vec![crate::Felt::new(550), crate::Felt::new(650), crate::Felt::new(750)];

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Seal with associated data
    let sealed = CryptoBox::seal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        AeadRpoKey,
        _,
    >(&mut rng, &public_key, &plaintext, &associated_data)
    .unwrap();

    // Unseal with same associated data should succeed
    let decrypted = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        AeadRpoKey,
    >(&secret_key, &sealed, &associated_data)
    .unwrap();

    assert_eq!(plaintext, decrypted);

    // Unseal with different associated data should fail
    let wrong_ad = vec![crate::Felt::new(111), crate::Felt::new(222)];
    let result = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::ecdsa_k256_keccak::PublicKey,
        AeadRpoKey,
    >(&secret_key, &sealed, &wrong_ad);
    assert!(result.is_err());
}

#[test]
fn test_x25519_aead_rpo_field_elements_roundtrip() {
    let mut rng = rand::rng();
    let plaintext = vec![crate::Felt::new(90), crate::Felt::new(91), crate::Felt::new(92)];
    let associated_data = vec![crate::Felt::new(900), crate::Felt::new(910)];

    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed = CryptoBox::seal_elements_with_associated_data::<
        crate::dsa::eddsa_25519::PublicKey,
        AeadRpoKey,
        _,
    >(&mut rng, &public_key, &plaintext, &associated_data)
    .unwrap();

    let decrypted = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::eddsa_25519::PublicKey,
        AeadRpoKey,
    >(&secret_key, &sealed, &associated_data)
    .unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_x25519_aead_rpo_field_elements_with_associated_data() {
    let mut rng = rand::rng();
    let plaintext = vec![crate::Felt::new(95), crate::Felt::new(96), crate::Felt::new(97)];
    let associated_data = vec![crate::Felt::new(950), crate::Felt::new(960), crate::Felt::new(970)];

    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Seal with associated data
    let sealed = CryptoBox::seal_elements_with_associated_data::<
        crate::dsa::eddsa_25519::PublicKey,
        AeadRpoKey,
        _,
    >(&mut rng, &public_key, &plaintext, &associated_data)
    .unwrap();

    // Unseal with same associated data should succeed
    let decrypted = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::eddsa_25519::PublicKey,
        AeadRpoKey,
    >(&secret_key, &sealed, &associated_data)
    .unwrap();

    assert_eq!(plaintext, decrypted);

    // Unseal with different associated data should fail
    let wrong_ad = vec![crate::Felt::new(777), crate::Felt::new(888)];
    let result = CryptoBox::unseal_elements_with_associated_data::<
        crate::dsa::eddsa_25519::PublicKey,
        AeadRpoKey,
    >(&secret_key, &sealed, &wrong_ad);
    assert!(result.is_err());
}

// Test that different keys produce different ciphertexts
#[test]
fn test_different_keys_different_ciphertexts() {
    let mut rng = rand::rng();
    let plaintext = b"test message";

    // Generate two different key pairs
    let secret1 = X25519SecretKey::with_rng(&mut rng);
    let public1 = secret1.public_key();
    let secret2 = X25519SecretKey::with_rng(&mut rng);
    let public2 = secret2.public_key();

    let sealed1 =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public1, plaintext, b"").unwrap();
    let sealed2 =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public2, plaintext, b"").unwrap();

    // Different keys should produce different ciphertexts
    assert_ne!(sealed1.ciphertext, sealed2.ciphertext);
}

// Test that wrong recipient key cannot decrypt
#[test]
fn test_wrong_recipient_key() {
    let mut rng = rand::rng();
    let plaintext = b"secret message";

    // Create intended recipient
    let recipient_key = X25519SecretKey::with_rng(&mut rng);
    let recipient_public = recipient_key.public_key();

    // Create wrong recipient (different person)
    let wrong_key = X25519SecretKey::with_rng(&mut rng);
    let _wrong_public = wrong_key.public_key();

    // Encrypt for the intended recipient
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &recipient_public, plaintext, b"").unwrap();

    // Try to decrypt with wrong recipient - should fail
    let result = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(
        &wrong_key, &sealed, b"",
    );

    // This assertion should now PASS - wrong recipient cannot decrypt!
    assert!(
        result.is_err(),
        "Decryption with wrong key should fail but it succeeded: {:?}",
        result
    );

    // Correct recipient should work
    let result = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(
        &recipient_key,
        &sealed,
        b"",
    );
    assert!(result.is_ok(), "Decryption with correct key should succeed");
    assert_eq!(result.unwrap(), plaintext);
}

// Test empty data
#[test]
fn test_empty_data() {
    let mut rng = rand::rng();
    let plaintext = b"";
    let ad = b"";

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, plaintext, ad).unwrap();
    let decrypted = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        ad,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

// ALGORITHM MISMATCH TESTS
// ================================================================================================

#[test]
fn test_algorithm_mismatch_k256_xchacha_vs_aead_rpo() {
    let mut rng = rand::rng();
    let plaintext = b"algorithm mismatch test";
    let ad = b"test context";

    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Encrypt with XChaCha20-Poly1305
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, plaintext, ad).unwrap();

    // Try to decrypt with AeadRpo (should fail due to algorithm mismatch)
    let result = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, AeadRpoKey>(
        &secret_key,
        &sealed,
        ad,
    );

    assert!(result.is_err(), "Decryption with wrong AEAD algorithm should fail");
}

#[test]
fn test_algorithm_mismatch_x25519_xchacha_vs_aead_rpo() {
    let mut rng = rand::rng();
    let plaintext = b"x25519 algorithm mismatch test";
    let ad = b"x25519 test context";

    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Encrypt with XChaCha20-Poly1305
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, plaintext, ad).unwrap();

    // Try to decrypt with AeadRpo (should fail due to algorithm mismatch)
    let result = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, AeadRpoKey>(
        &secret_key,
        &sealed,
        ad,
    );

    assert!(result.is_err(), "Decryption with wrong AEAD algorithm should fail");
}

#[test]
fn test_cross_curve_mismatch_k256_vs_x25519() {
    let mut rng = rand::rng();
    let plaintext = b"cross-curve mismatch test";
    let ad = b"cross-curve context";

    // Generate keys for different curves
    let k256_secret_key = K256SecretKey::with_rng(&mut rng);
    let k256_public_key = k256_secret_key.public_key();
    let x25519_secret_key = X25519SecretKey::with_rng(&mut rng);
    let _x25519_public_key = x25519_secret_key.public_key();

    // Encrypt for K256 recipient
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &k256_public_key, plaintext, ad).unwrap();

    // Try to decrypt with X25519 key (should fail due to curve mismatch)
    let result = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(
        &x25519_secret_key,
        &sealed,
        ad,
    );

    assert!(result.is_err(), "Decryption with wrong curve key should fail");

    // Verify that correct K256 key can still decrypt
    let result = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(
        &k256_secret_key,
        &sealed,
        ad,
    );
    assert!(result.is_ok(), "Decryption with correct key should succeed");
    assert_eq!(result.unwrap(), plaintext);
}

// EPHEMERAL KEY SERIALIZATION TESTS
// ================================================================================================

#[test]
fn test_ephemeral_key_serialization_k256() {
    let mut rng = rand::rng();
    let secret_key = K256SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Create a sealed message
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, b"test", b"").unwrap();

    // Extract ephemeral key from sealed message
    let ephemeral_bytes = &sealed.ephemeral_public_key;

    // Deserialize and verify the ephemeral public key
    let _reconstructed_ephemeral_public_key =
        crate::ecdh::k256::EphemeralPublicKey::read_from_bytes(ephemeral_bytes)
            .expect("Failed to deserialize K256 ephemeral public key");

    // The reconstructed key should be able to decrypt the original message
    let decrypted = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        b"",
    )
    .expect("Failed to decrypt with original sealed message");

    assert_eq!(decrypted, b"test");

    // Test with a different message to verify the reconstructed key works properly
    let test_plaintext = b"another test message";
    let test_sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, test_plaintext, b"").unwrap();

    let decrypted_test =
        unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(
            &secret_key,
            &test_sealed,
            b"",
        )
        .expect("Failed to decrypt test message");

    assert_eq!(decrypted_test, test_plaintext);
}

#[test]
fn test_ephemeral_key_serialization_x25519() {
    let mut rng = rand::rng();
    let secret_key = X25519SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Create a sealed message
    let sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, b"test", b"").unwrap();

    // Extract ephemeral key from sealed message
    let ephemeral_bytes = &sealed.ephemeral_public_key;

    // Deserialize and verify the ephemeral public key
    let _reconstructed_ephemeral_public_key =
        crate::ecdh::x25519::EphemeralPublicKey::read_from_bytes(ephemeral_bytes)
            .expect("Failed to deserialize X25519 ephemeral public key");

    // The reconstructed key should be able to decrypt the original message
    let decrypted = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(
        &secret_key,
        &sealed,
        b"",
    )
    .expect("Failed to decrypt with original sealed message");

    assert_eq!(decrypted, b"test");

    // Test with a different message to verify the reconstructed key works properly
    let test_plaintext = b"x25519 another test message";
    let test_sealed =
        seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, test_plaintext, b"").unwrap();

    let decrypted_test = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(
        &secret_key,
        &test_sealed,
        b"",
    )
    .expect("Failed to decrypt test message");

    assert_eq!(decrypted_test, test_plaintext);
}

// PROPERTY-BASED TESTS
// ================================================================================================

#[cfg(feature = "std")]
mod property_tests {
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;

    /// Generates arbitrary byte vectors using the same pattern as existing AEAD tests
    fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..500)
    }

    /// Generates arbitrary field element vectors using the same pattern as AEAD tests
    fn arbitrary_field_elements() -> impl Strategy<Value = Vec<crate::Felt>> {
        (1usize..100, any::<u64>()).prop_map(|(len, seed)| {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            (0..len).map(|_| crate::Felt::new(rng.next_u64())).collect()
        })
    }

    proptest! {
        #[test]
        fn prop_k256_xchacha_bytes_roundtrip(
            plaintext in arbitrary_bytes(),
            associated_data in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            let secret_key = K256SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let _aead_key = XChaChaKey::with_rng(&mut rng);

            let sealed = seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, &plaintext, &associated_data).unwrap();
            let decrypted = unseal_with_new_api::<crate::dsa::ecdsa_k256_keccak::PublicKey, XChaChaKey>(&secret_key, &sealed, &associated_data).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn prop_x25519_xchacha_bytes_roundtrip(
            plaintext in arbitrary_bytes(),
            associated_data in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            let secret_key = X25519SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let _aead_key = XChaChaKey::with_rng(&mut rng);

            let sealed = seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, &plaintext, &associated_data).unwrap();
            let decrypted = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(&secret_key, &sealed, &associated_data).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn prop_x25519_aead_rpo_bytes_roundtrip(
            plaintext in arbitrary_bytes(),
            associated_data in arbitrary_bytes()
        ) {
            let mut rng = rand::rng();
            let secret_key = X25519SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();

            let sealed = seal_with_new_api::<_, AeadRpoKey, _>(&mut rng, &public_key, &plaintext, &associated_data).unwrap();
            let decrypted = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, AeadRpoKey>(&secret_key, &sealed, &associated_data).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn prop_x25519_aead_rpo_elements_roundtrip(
            plaintext in arbitrary_field_elements(),
            associated_data in arbitrary_field_elements()
        ) {
            let mut rng = rand::rng();
            let secret_key = X25519SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();

            let sealed = CryptoBox::seal_elements_with_associated_data::<crate::dsa::eddsa_25519::PublicKey, AeadRpoKey, _>(
                &mut rng, &public_key, &plaintext, &associated_data
            ).unwrap();
            let decrypted = CryptoBox::unseal_elements_with_associated_data::<crate::dsa::eddsa_25519::PublicKey, AeadRpoKey>(
                &secret_key, &sealed, &associated_data
            ).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn prop_wrong_associated_data_detection(
            plaintext in arbitrary_bytes(),
            correct_ad in arbitrary_bytes(),
            wrong_ad in arbitrary_bytes()
        ) {
            // Skip test if associated data is the same
            prop_assume!(correct_ad != wrong_ad);

            let mut rng = rand::rng();
            let secret_key = X25519SecretKey::with_rng(&mut rng);
            let public_key = secret_key.public_key();
            let _aead_key = XChaChaKey::with_rng(&mut rng);

            let sealed = seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public_key, &plaintext, &correct_ad).unwrap();
            let result = unseal_with_new_api::<crate::dsa::eddsa_25519::PublicKey, XChaChaKey>(&secret_key, &sealed, &wrong_ad);

            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_different_keys_different_ciphertexts(
            plaintext in arbitrary_bytes()
        ) {
            prop_assume!(!plaintext.is_empty()); // Skip empty plaintexts

            let mut rng = rand::rng();

            // Generate two different key pairs
            let secret1 = X25519SecretKey::with_rng(&mut rng);
            let public1 = secret1.public_key();
            let secret2 = X25519SecretKey::with_rng(&mut rng);
            let public2 = secret2.public_key();

            let _aead_key = XChaChaKey::with_rng(&mut rng);

            let sealed1 = seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public1, &plaintext, b"").unwrap();
            let sealed2 = seal_with_new_api::<_, XChaChaKey, _>(&mut rng, &public2, &plaintext, b"").unwrap();

            // Different keys should produce different ciphertexts
            prop_assert_ne!(sealed1.ciphertext, sealed2.ciphertext);
        }
    }
}
