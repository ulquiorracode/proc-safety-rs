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
        #[cfg(windows)]
        let builder = ProcessSafety::builder()
            .strict_handle_checks()
            .hide_current_thread();

        #[cfg(unix)]
        let builder = ProcessSafety::builder().disable_core_dumps();

        // Should commit without panic on native host
        let result = builder.commit();
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_safety_builder_best_effort() {
        let builder = ProcessSafety::builder()
            .strict_handle_checks()
            .hide_current_thread()
            .disable_core_dumps()
            .best_effort(true);

        assert!(builder.commit().is_ok());
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

        #[cfg(unix)]
        {
            // Windows policies are rejected on Unix when best_effort is false
            let strict_builder = ProcessSafety::builder().strict_handle_checks();
            assert!(matches!(
                strict_builder.commit(),
                Err(SafetyError::UnsupportedPlatform)
            ));

            let best_effort_builder = ProcessSafety::builder()
                .strict_handle_checks()
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

        #[cfg(unix)]
        {
            let dump_res = os::unix::enforce_disable_dumpable();
            println!("enforce_disable_dumpable: {:?}", dump_res);
            assert!(dump_res.is_ok());
        }
    }

    #[test]
    fn test_protect_memory_range_overflow_rejection() {
        #[cfg(windows)]
        {
            unsafe {
                let bad_ptr = (usize::MAX - 64) as *mut u8;
                let res = os::windows::protect_memory_range(
                    bad_ptr,
                    128,
                    windows_sys::Win32::System::Memory::PAGE_READONLY,
                );
                assert!(matches!(res, Err(SafetyError::InvalidBufferRange)));
            }
        }

        #[cfg(unix)]
        {
            unsafe {
                let bad_ptr = (usize::MAX - 64) as *mut u8;
                let res = os::unix::protect_memory_range(bad_ptr, 128, libc::PROT_READ);
                assert!(matches!(res, Err(SafetyError::InvalidBufferRange)));
            }
        }
    }

    #[cfg(feature = "stitch")]
    #[test]
    fn test_proc_safety_middleware_stitch_layer() {
        use stitch_core::flow::FlowControl;
        use stitch_core::middleware::Layer;

        let middleware = ProcSafetyMiddleware;
        let mut ctx = ();
        let intent = 42;
        let flow: FlowControl<i32, (), ()> =
            Layer::<(), i32, (), ()>::on_enter(&middleware, &mut ctx, intent);
        assert!(matches!(flow, FlowControl::Proceed(42)));

        let mut outcome: Result<i32, ()> = Ok(100);
        Layer::<(), i32, i32, ()>::on_exit(&middleware, &mut ctx, &mut outcome);
        assert_eq!(outcome, Ok(100));
    }
}
