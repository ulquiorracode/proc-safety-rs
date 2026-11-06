//! Unix/Linux process safety and anti-ptrace mitigations.

use crate::error::SafetyError;

#[cfg(target_os = "linux")]
pub fn enforce_disable_dumpable() -> Result<(), SafetyError> {
    unsafe {
        // prctl(PR_SET_DUMPABLE, 0)
        let ret = libc::prctl(libc::PR_SET_DUMPABLE, 0);
        if ret != 0 {
            return Err(SafetyError::OsPolicyRejection(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u32,
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enforce_disable_dumpable() -> Result<(), SafetyError> {
    Ok(())
}

/// Sets page protection on a memory range using `mprotect`.
pub unsafe fn protect_memory_range(
    ptr: *mut u8,
    len: usize,
    prot: libc::c_int,
) -> Result<(), SafetyError> {
    let ret = unsafe { libc::mprotect(ptr as *mut _, len, prot) };
    if ret != 0 {
        return Err(SafetyError::PageProtectionFailed(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u32,
        ));
    }
    Ok(())
}
