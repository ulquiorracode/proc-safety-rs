//! Windows kernel mitigation policies and anti-tamper interfaces.

use crate::error::SafetyError;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, VirtualProtect};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, ProcessDynamicCodePolicy, ProcessSignaturePolicy,
    ProcessStrictHandleCheckPolicy, SetProcessMitigationPolicy,
};

/// Sets dynamic code prohibition (disallows creating RWX or executable heap pages).
pub fn enforce_prohibit_dynamic_code() -> Result<(), SafetyError> {
    // PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
    // Flags: ProhibitDynamicCode = 1
    #[repr(C)]
    struct DynamicCodePolicyStruct {
        flags: u32,
    }

    let policy = DynamicCodePolicyStruct { flags: 1 };

    unsafe {
        let ret = SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            &policy as *const _ as *const _,
            core::mem::size_of::<DynamicCodePolicyStruct>(),
        );

        if ret == 0 {
            let err = GetLastError();
            // ERROR_ACCESS_DENIED or ERROR_NOT_SUPPORTED
            return Err(SafetyError::OsPolicyRejection(err));
        }
    }

    Ok(())
}

/// Restricts loaded DLLs strictly to Microsoft or authorized signatures.
pub fn enforce_block_unsigned_binaries() -> Result<(), SafetyError> {
    // PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
    // MicrosoftSignedOnly = 1
    #[repr(C)]
    struct BinarySignaturePolicyStruct {
        flags: u32,
    }

    let policy = BinarySignaturePolicyStruct { flags: 1 };

    unsafe {
        let ret = SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            &policy as *const _ as *const _,
            core::mem::size_of::<BinarySignaturePolicyStruct>(),
        );

        if ret == 0 {
            let err = GetLastError();
            return Err(SafetyError::OsPolicyRejection(err));
        }
    }

    Ok(())
}

/// Enforces strict kernel handle checking (raises immediate exception on bad handle usage).
pub fn enforce_strict_handle_checks() -> Result<(), SafetyError> {
    // PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
    // RaiseExceptionOnInvalidHandleReference = 1, HandleExceptionsPermanentlyEnabled = 1
    #[repr(C)]
    struct StrictHandleCheckPolicyStruct {
        flags: u32,
    }

    let policy = StrictHandleCheckPolicyStruct { flags: 0b11 };

    unsafe {
        let ret = SetProcessMitigationPolicy(
            ProcessStrictHandleCheckPolicy,
            &policy as *const _ as *const _,
            core::mem::size_of::<StrictHandleCheckPolicyStruct>(),
        );

        if ret == 0 {
            let err = GetLastError();
            return Err(SafetyError::OsPolicyRejection(err));
        }
    }

    Ok(())
}

/// Hides a thread from user-mode debuggers using `NtSetInformationThread` (ThreadHideFromDebugger = 0x11).
///
/// # Safety
///
/// `thread` must be a valid OS thread handle with `THREAD_SET_INFORMATION` access rights.
pub unsafe fn hide_thread(thread: HANDLE) -> Result<(), SafetyError> {
    // Dynamically link NtSetInformationThread from ntdll.dll
    type NtSetInformationThreadFn = unsafe extern "system" fn(
        thread_handle: HANDLE,
        thread_information_class: u32,
        thread_information: *const core::ffi::c_void,
        thread_information_length: u32,
    ) -> i32;

    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            return Err(SafetyError::ThreadProtectionFailed(GetLastError()));
        }

        let proc = GetProcAddress(ntdll, c"NtSetInformationThread".as_ptr().cast());

        if let Some(func) = proc {
            let nt_set_info: NtSetInformationThreadFn = core::mem::transmute(func);
            const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;

            let status = nt_set_info(thread, THREAD_HIDE_FROM_DEBUGGER, core::ptr::null(), 0);
            if status < 0 {
                return Err(SafetyError::ThreadProtectionFailed(status as u32));
            }
        } else {
            return Err(SafetyError::ThreadProtectionFailed(GetLastError()));
        }
    }

    Ok(())
}

/// Hides the currently calling thread from debuggers.
pub fn hide_current_thread() -> Result<(), SafetyError> {
    let current = unsafe { GetCurrentThread() };
    // SAFETY: GetCurrentThread returns a valid pseudo-handle to the current thread.
    unsafe { hide_thread(current) }
}

/// Sets protection on a memory page range (e.g. `PAGE_READONLY` or `PAGE_GUARD`).
///
/// # Safety
///
/// `ptr` must point to a valid, committed virtual memory range of at least `len` bytes.
/// Caller must ensure that changing protection does not invalidate active references or violate Rust aliasing rules.
pub unsafe fn protect_memory_range(
    ptr: *mut u8,
    len: usize,
    new_protect: PAGE_PROTECTION_FLAGS,
) -> Result<PAGE_PROTECTION_FLAGS, SafetyError> {
    let mut old_protect = 0;
    let ret = unsafe { VirtualProtect(ptr.cast(), len, new_protect, &mut old_protect) };
    if ret == 0 {
        return Err(SafetyError::PageProtectionFailed(unsafe { GetLastError() }));
    }
    Ok(old_protect)
}
