//! Page-aligned hardware-protected memory buffers with zero-cost sealing and volatile scrubbing.

use crate::error::SafetyError;

#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualProtect,
};

/// Hardware access level for a protected memory page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageAccess {
    /// Read-write access (normal memory).
    ReadWrite,
    /// Read-only access (hardware traps any write attempts with access violation).
    ReadOnly,
    /// No access (hardware traps any read or write attempts).
    NoAccess,
}

/// Returns the system virtual memory page size in bytes.
#[inline]
pub fn system_page_size() -> usize {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        let mut info: SYSTEM_INFO = unsafe { core::mem::zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        info.dwPageSize as usize
    }
    #[cfg(unix)]
    {
        let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if sz > 0 { sz as usize } else { 4096 }
    }
    #[cfg(not(any(windows, unix)))]
    {
        4096
    }
}

/// A dedicated, page-aligned virtual memory region with hardware-enforced protection.
///
/// Ensures zero-compromise security:
/// - Allocated directly via OS virtual memory primitives (`VirtualAlloc` / `mmap`).
/// - Never shares pages with other heap allocations (eliminates cross-allocation side effects).
/// - Hardware-enforced sealing (`PAGE_READONLY`, `PAGE_NOACCESS`).
/// - Memory is securely scrubbed via volatile zeroing on drop before being released to the OS.
#[derive(Debug)]
pub struct ProtectedMemory {
    ptr: *mut u8,
    aligned_len: usize,
    user_len: usize,
    access: PageAccess,
}

// SAFETY: ProtectedMemory exclusively owns its raw memory pointer.
unsafe impl Send for ProtectedMemory {}
// SAFETY: Mutation requires exclusive `&mut` reference, making read-only shared access thread-safe.
unsafe impl Sync for ProtectedMemory {}

impl ProtectedMemory {
    /// Allocates a new protected memory buffer of at least `len` bytes.
    ///
    /// The buffer is page-aligned and has `PageAccess::ReadWrite` initially.
    pub fn allocate(len: usize) -> Result<Self, SafetyError> {
        if len == 0 {
            return Err(SafetyError::Violation(
                "Cannot allocate 0 bytes of protected memory".into(),
            ));
        }

        let page_size = system_page_size();
        let aligned_len = len
            .checked_add(page_size - 1)
            .map(|sum| sum & !(page_size - 1))
            .ok_or_else(|| SafetyError::Violation("Allocation size arithmetic overflow".into()))?;

        let ptr: *mut u8;

        #[cfg(windows)]
        {
            unsafe {
                let mem = VirtualAlloc(
                    core::ptr::null(),
                    aligned_len,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if mem.is_null() {
                    return Err(SafetyError::PageProtectionFailed(
                        windows_sys::Win32::Foundation::GetLastError(),
                    ));
                }
                ptr = mem.cast();
            }
        }

        #[cfg(unix)]
        {
            unsafe {
                let mem = libc::mmap(
                    core::ptr::null_mut(),
                    aligned_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                    -1,
                    0,
                );
                if mem == libc::MAP_FAILED {
                    return Err(SafetyError::PageProtectionFailed(
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u32,
                    ));
                }
                ptr = mem.cast();
            }
        }

        Ok(Self {
            ptr,
            aligned_len,
            user_len: len,
            access: PageAccess::ReadWrite,
        })
    }

    /// Returns the user-requested length of the protected buffer in bytes.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.user_len
    }

    /// Returns whether the buffer length is 0.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.user_len == 0
    }

    /// Returns the current hardware access mode.
    #[inline(always)]
    pub fn access(&self) -> PageAccess {
        self.access
    }

    /// Modifies the hardware page access permissions for this buffer.
    pub fn protect(&mut self, access: PageAccess) -> Result<(), SafetyError> {
        if self.access == access {
            return Ok(());
        }

        #[cfg(windows)]
        {
            let prot: PAGE_PROTECTION_FLAGS = match access {
                PageAccess::ReadWrite => PAGE_READWRITE,
                PageAccess::ReadOnly => PAGE_READONLY,
                PageAccess::NoAccess => PAGE_NOACCESS,
            };

            let mut old_protect = 0;
            let ret = unsafe {
                VirtualProtect(self.ptr.cast(), self.aligned_len, prot, &mut old_protect)
            };
            if ret == 0 {
                return Err(SafetyError::PageProtectionFailed(unsafe {
                    windows_sys::Win32::Foundation::GetLastError()
                }));
            }
        }

        #[cfg(unix)]
        {
            let prot = match access {
                PageAccess::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
                PageAccess::ReadOnly => libc::PROT_READ,
                PageAccess::NoAccess => libc::PROT_NONE,
            };

            let ret = unsafe { libc::mprotect(self.ptr.cast(), self.aligned_len, prot) };
            if ret != 0 {
                return Err(SafetyError::PageProtectionFailed(
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u32,
                ));
            }
        }

        self.access = access;
        Ok(())
    }

    /// Accesses the underlying memory as an immutable byte slice.
    ///
    /// Fails with `SafetyError::Violation` if the page is currently sealed with `PageAccess::NoAccess`.
    pub fn as_slice(&self) -> Result<&[u8], SafetyError> {
        if self.access == PageAccess::NoAccess {
            return Err(SafetyError::Violation(
                "Cannot read from memory page configured with PageAccess::NoAccess".into(),
            ));
        }

        // SAFETY: Pointer is valid, aligned, non-null, and backed by accessible memory.
        Ok(unsafe { core::slice::from_raw_parts(self.ptr, self.user_len) })
    }

    /// Accesses the underlying memory as a mutable byte slice.
    ///
    /// Fails with `SafetyError::Violation` if the page is not in `PageAccess::ReadWrite` mode.
    pub fn as_mut_slice(&mut self) -> Result<&mut [u8], SafetyError> {
        if self.access != PageAccess::ReadWrite {
            return Err(SafetyError::Violation(
                "Cannot mutate memory page that is sealed as ReadOnly or NoAccess".into(),
            ));
        }

        // SAFETY: Pointer is valid, aligned, uniquely borrowed via &mut self, and backed by writable memory.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.ptr, self.user_len) })
    }

    /// Seals the memory buffer as `ReadOnly` for the lifetime of a RAII guard.
    ///
    /// When the guard is dropped, the memory is automatically restored to its previous access level.
    pub fn seal_guard(&mut self) -> Result<ReadOnlyGuard<'_>, SafetyError> {
        let prev = self.access;
        self.protect(PageAccess::ReadOnly)?;
        Ok(ReadOnlyGuard {
            mem: self,
            previous_access: prev,
        })
    }
}

impl Drop for ProtectedMemory {
    fn drop(&mut self) {
        // Unseal back to ReadWrite if needed so we can safely scrub secrets.
        // If unsealing fails, we skip scrubbing to prevent uncatchable 0xC0000005 access violation.
        let can_scrub = if self.access != PageAccess::ReadWrite {
            self.protect(PageAccess::ReadWrite).is_ok()
        } else {
            true
        };

        if can_scrub {
            // Memory barrier before volatile writes
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            // Fast word-aligned clearing followed by remainder bytes
            unsafe {
                let word_size = core::mem::size_of::<usize>();
                let aligned_words = self.aligned_len / word_size;
                let word_ptr = self.ptr.cast::<usize>();

                for i in 0..aligned_words {
                    core::ptr::write_volatile(word_ptr.add(i), 0);
                }

                let remaining_start = aligned_words * word_size;
                for i in remaining_start..self.aligned_len {
                    core::ptr::write_volatile(self.ptr.add(i), 0);
                }
            }

            // Memory barrier after volatile writes
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }

        #[cfg(windows)]
        {
            unsafe {
                VirtualFree(self.ptr.cast(), 0, MEM_RELEASE);
            }
        }

        #[cfg(unix)]
        {
            unsafe {
                libc::munmap(self.ptr.cast(), self.aligned_len);
            }
        }
    }
}

/// RAII guard sealing a `ProtectedMemory` buffer as `ReadOnly`.
pub struct ReadOnlyGuard<'a> {
    mem: &'a mut ProtectedMemory,
    previous_access: PageAccess,
}

impl<'a> ReadOnlyGuard<'a> {
    /// Returns the underlying byte slice while sealed.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: While ReadOnlyGuard is alive, the memory is sealed ReadOnly and guaranteed valid.
        unsafe { core::slice::from_raw_parts(self.mem.ptr, self.mem.user_len) }
    }
}

impl<'a> Drop for ReadOnlyGuard<'a> {
    fn drop(&mut self) {
        let _ = self.mem.protect(self.previous_access);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_memory_lifecycle() {
        let mut mem = ProtectedMemory::allocate(64).expect("allocation should succeed");
        assert_eq!(mem.len(), 64);
        assert_eq!(mem.access(), PageAccess::ReadWrite);

        // Mutate memory
        {
            let slice = mem.as_mut_slice().expect("should be mutable");
            slice[0] = 0xAA;
            slice[63] = 0xBB;
        }

        // Read memory
        {
            let slice = mem.as_slice().expect("should be readable");
            assert_eq!(slice[0], 0xAA);
            assert_eq!(slice[63], 0xBB);
        }

        // Seal ReadOnly
        mem.protect(PageAccess::ReadOnly).expect("seal to ReadOnly");
        assert_eq!(mem.access(), PageAccess::ReadOnly);
        assert!(mem.as_mut_slice().is_err());
        assert_eq!(mem.as_slice().unwrap()[0], 0xAA);

        // Seal NoAccess
        mem.protect(PageAccess::NoAccess).expect("seal to NoAccess");
        assert_eq!(mem.access(), PageAccess::NoAccess);
        assert!(mem.as_slice().is_err());
        assert!(mem.as_mut_slice().is_err());

        // Restore ReadWrite
        mem.protect(PageAccess::ReadWrite)
            .expect("restore ReadWrite");
        assert_eq!(mem.as_slice().unwrap()[0], 0xAA);
    }

    #[test]
    fn test_seal_guard_restores_previous_state() {
        let mut mem = ProtectedMemory::allocate(32).expect("allocation should succeed");
        {
            let slice = mem.as_mut_slice().unwrap();
            slice[0] = 42;
        }

        // Test restore to ReadWrite
        {
            let guard = mem.seal_guard().expect("guard creation succeeds");
            assert_eq!(guard.as_slice()[0], 42);
        }
        assert_eq!(mem.access(), PageAccess::ReadWrite);

        // Test restore to NoAccess
        mem.protect(PageAccess::NoAccess).unwrap();
        {
            let guard = mem.seal_guard().expect("guard creation from NoAccess");
            assert_eq!(guard.as_slice()[0], 42);
        }
        assert_eq!(mem.access(), PageAccess::NoAccess);
    }

    #[test]
    fn test_overflow_protection() {
        let res = ProtectedMemory::allocate(usize::MAX);
        assert!(res.is_err());
    }
}
