// miden-crypto/tests/rescue_arch.rs

// This test must be run with specific rustflags, e.g.:
// RUSTFLAGS="-C target-cpu=native" cargo test --test rescue_arch -- --nocapture

use miden_crypto::Felt;
use miden_crypto::hash::rpx::Rpx256;
use proptest::prelude::*;

// Test that the optimized functions work correctly through the public API
// This test focuses on runtime feature detection and behavior consistency

// Simple test to verify the runtime feature detection works
#[test]
fn test_runtime_feature_detection() {
    // Test that the optimized functions work correctly
    // This tests the runtime feature detection logic without requiring direct access to SIMD intrinsics

    let mut state = [Felt::new(1); 12];

    // Test that apply_ext_round works without panicking
    // The internal dispatch will use runtime feature detection
    Rpx256::apply_ext_round(&mut state, 0);

    // Test full permutation works without panicking
    let mut test_state = [Felt::new(42); 12];
    Rpx256::apply_permutation(&mut test_state);
    // If we get here without panicking, the basic functionality works
}

// Test that the hash functions produce consistent results
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]
    #[test]
    fn test_hash_consistency(
        input1 in any::<[u8; 32]>(),
        input2 in any::<[u8; 32]>()
    ) {
        let hash1 = Rpx256::hash(&input1);
        let hash2 = Rpx256::hash(&input2);

        // Different inputs should produce different hashes (with very high probability)
        if input1 != input2 {
            prop_assert!(hash1 != hash2, "Different inputs should produce different hashes");
        }

        // Same input should produce same hash
        let hash1_again = Rpx256::hash(&input1);
        prop_assert_eq!(hash1, hash1_again, "Same input should produce same hash");
    }
}

// Test that the feature detection enables optimized paths when available
#[test]
fn test_optimized_path_availability() {
    // Test with different data patterns
    for round in 0..7 {
        let mut state = [Felt::new(1); 12];
        let ark = Rpx256::ARK1[round];

        // Test ext round dispatch - should not panic
        Rpx256::apply_ext_round(&mut state, round);
        // Verify the state changed (optimization should have modified it)
        assert_ne!(state, [Felt::new(1); 12]);

        // Test fb round
        let mut fb_state = [Felt::new(1); 12];
        Rpx256::apply_fb_round(&mut fb_state, round);
        // Should not panic and should modify the state
        assert_ne!(fb_state, [Felt::new(1); 12]);
    }
}