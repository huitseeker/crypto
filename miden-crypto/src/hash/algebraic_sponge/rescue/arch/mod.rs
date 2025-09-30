// Keep SVE implementation as-is since it uses a different mechanism (FFI).
#[cfg(target_feature = "sve")]
pub mod sve_ffi {
    use crate::{Felt, hash::algebraic_sponge::rescue::STATE_WIDTH};

    mod ffi {
        #[link(name = "rpo_sve", kind = "static")]
        extern "C" {
            pub fn add_constants_and_apply_sbox(
                state: *mut std::ffi::c_ulong,
                constants: *const std::ffi::c_ulong,
            ) -> bool;
            pub fn add_constants_and_apply_inv_sbox(
                state: *mut std::ffi::c_ulong,
                constants: *const std::ffi::c_ulong,
            ) -> bool;
        }
    }

    #[inline(always)]
    pub fn add_constants_and_apply_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        unsafe {
            ffi::add_constants_and_apply_sbox(
                state.as_mut_ptr() as *mut u64,
                ark.as_ptr() as *const u64,
            )
        }
    }

    #[inline(always)]
    pub fn add_constants_and_apply_inv_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        unsafe {
            ffi::add_constants_and_apply_inv_sbox(
                state.as_mut_ptr() as *mut u64,
                ark.as_ptr() as *const u64,
            )
        }
    }
}

// Import the x86 modules unconditionally
mod x86_64_avx2;
mod x86_64_avx512;

pub mod optimized {
    use crate::{Felt, hash::algebraic_sponge::rescue::{STATE_WIDTH, add_constants}};
    use super::{x86_64_avx2, x86_64_avx512};
    #[cfg(all(target_arch = "x86_64", std))]
    use std::is_x86_feature_detected;

    #[inline(always)]
    pub fn add_constants_and_apply_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        // Dispatch logic: check for the most powerful feature first.
        // Note: is_x86_feature_detected is only available in std builds
        #[cfg(std)]
        {
            if is_x86_feature_detected!("avx512f") {
                add_constants(state, ark);
                // SAFETY: We have checked that the avx512f feature is available at runtime.
                unsafe {
                    x86_64_avx512::apply_sbox(core::mem::transmute(state));
                }
                return true;
            }
            if is_x86_feature_detected!("avx2") {
                add_constants(state, ark);
                // SAFETY: We have checked that the avx2 feature is available at runtime.
                unsafe {
                    x86_64_avx2::apply_sbox(core::mem::transmute(state));
                }
                return true;
            }
        }

        // SVE FFI or fallback for other architectures/builds
        #[cfg(target_feature = "sve")]
        {
            if super::sve_ffi::add_constants_and_apply_sbox(state, ark) {
                return true;
            }
        }

        // Fallback case
        false
    }

    #[inline(always)]
    pub fn add_constants_and_apply_inv_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        // Note: is_x86_feature_detected is only available in std builds
        #[cfg(std)]
        {
            if is_x86_feature_detected!("avx512f") {
                add_constants(state, ark);
                unsafe { x86_64_avx512::apply_inv_sbox(core::mem::transmute(state)); }
                return true;
            }
            if is_x86_feature_detected!("avx2") {
                add_constants(state, ark);
                unsafe { x86_64_avx2::apply_inv_sbox(core::mem::transmute(state)); }
                return true;
            }
        }
        #[cfg(target_feature = "sve")]
        {
            if super::sve_ffi::add_constants_and_apply_inv_sbox(state, ark) {
                return true;
            }
        }
        false
    }

    #[inline(always)]
    pub fn add_constants_and_apply_ext_round(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        // Note: is_x86_feature_detected is only available in std builds
        #[cfg(std)]
        {
            if is_x86_feature_detected!("avx512f") {
                add_constants(state, ark);
                unsafe { x86_64_avx512::apply_ext_round(core::mem::transmute(state)); }
                return true;
            }
            if is_x86_feature_detected!("avx2") {
                add_constants(state, ark);
                unsafe { x86_64_avx2::apply_ext_round(core::mem::transmute(state)); }
                return true;
            }
        }
        // No SVE implementation for ext_round exists, so we just fallback.
        false
    }
}
