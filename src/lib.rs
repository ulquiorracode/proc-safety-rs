//! Zero-cost, internal process self-defense, memory boundaries, and OS kernel mitigation policies.

pub mod error;
pub mod mem;
pub mod os;
pub mod policy;
pub mod stitch_support;

pub use error::SafetyError;
pub use mem::{PageAccess, ProtectedMemory, ReadOnlyGuard};
pub use policy::{ProcessSafety, ProcessSafetyBuilder};
pub use stitch_support::ProcSafetyMiddleware;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_safety_builder_compiles_and_commits() {
        let builder = ProcessSafety::builder()
            .strict_handle_checks()
            .hide_current_thread();

        // Should commit without panic
        let result = builder.commit();
        assert!(result.is_ok());
    }

    #[test]
    fn test_fail_fast_cross_platform_policy() {
        #[cfg(windows)]
        {
            // disable_core_dumps is unix-only
            let strict_builder = ProcessSafety::builder().disable_core_dumps();
            assert!(matches!(
                strict_builder.commit(),
                Err(SafetyError::UnsupportedPlatform)
            ));

            let best_effort_builder = ProcessSafety::builder()
                .disable_core_dumps()
                .best_effort(true);
            assert!(best_effort_builder.commit().is_ok());
        }
    }

    #[test]
    fn test_null_thread_handle_rejection() {
        #[cfg(windows)]
        {
            unsafe {
                let res = os::windows::hide_thread(core::ptr::null_mut());
                assert!(matches!(res, Err(SafetyError::Violation(_))));
            }
        }
    }

    #[test]
    fn test_individual_mitigations() {
        #[cfg(windows)]
        {
            let handle_res = os::windows::enforce_strict_handle_checks();
            println!("strict_handle_checks 1: {:?}", handle_res);
            let handle_res2 = os::windows::enforce_strict_handle_checks();
            println!("strict_handle_checks 2: {:?}", handle_res2);

            let hide_res = os::windows::hide_current_thread();
            println!("hide_current_thread 1: {:?}", hide_res);
            let hide_res2 = os::windows::hide_current_thread();
            println!("hide_current_thread 2: {:?}", hide_res2);

            let dyn_res = os::windows::enforce_prohibit_dynamic_code();
            println!("prohibit_dynamic_code 1: {:?}", dyn_res);
            let dyn_res2 = os::windows::enforce_prohibit_dynamic_code();
            println!("prohibit_dynamic_code 2: {:?}", dyn_res2);

            let sign_res = os::windows::enforce_block_unsigned_binaries();
            println!("block_unsigned_binaries 1: {:?}", sign_res);
            let sign_res2 = os::windows::enforce_block_unsigned_binaries();
            println!("block_unsigned_binaries 2: {:?}", sign_res2);
        }
    }
}
