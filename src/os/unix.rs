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
    Err(SafetyError::UnsupportedPlatform)
}

/// Sets page protection on a memory range using `mprotect`, automatically aligning to system page boundary.
///
/// # Safety
///
/// `ptr` must point to a valid, committed virtual memory range of at least `len` bytes.
pub unsafe fn protect_memory_range(
    ptr: *mut u8,
    len: usize,
    prot: libc::c_int,
) -> Result<(), SafetyError> {
    if len == 0 {
        return Ok(());
    }

    let page_size = crate::mem::system_page_size();
    let addr = ptr as usize;
    let page_start = addr & !(page_size - 1);
    let page_offset = addr - page_start;
    let aligned_len = (len + page_offset + page_size - 1) & !(page_size - 1);

    let ret = unsafe { libc::mprotect(page_start as *mut _, aligned_len, prot) };
    if ret != 0 {
        return Err(SafetyError::PageProtectionFailed(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u32,
        ));
    }
    Ok(())
}
