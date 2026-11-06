//! High-level declarative builder and orchestrator for internal process safety.

use crate::error::SafetyError;
use crate::os;

/// Builder to configure and atomically commit process-wide safety and kernel mitigation policies.
#[derive(Debug, Default, Clone)]
pub struct ProcessSafetyBuilder {
    pub block_unsigned_binaries: bool,
    pub prohibit_dynamic_code: bool,
    pub strict_handle_checks: bool,
    pub hide_current_thread: bool,
    pub disable_core_dumps: bool,
    pub best_effort: bool,
}

impl ProcessSafetyBuilder {
    /// Creates a new uncommitted process safety builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// When enabled, ignores platform-unsupported policies instead of returning `SafetyError::UnsupportedPlatform`.
    pub fn best_effort(mut self, enabled: bool) -> Self {
        self.best_effort = enabled;
        self
    }

    /// Restricts loaded DLLs strictly to Microsoft or authorized root CA signatures.
    ///
    /// # Warning
    ///
    /// On Windows, this sets `MicrosoftSignedOnly`. Any subsequent attempt to load third-party
    /// display drivers (NVIDIA, AMD), Vulkan ICDs, OpenAL, game overlays (Steam, Discord), or
    /// native mod DLLs without a Microsoft signature will immediately fail with `ERROR_INVALID_IMAGE_HASH`.
    pub fn block_unsigned_binaries(mut self) -> Self {
        self.block_unsigned_binaries = true;
        self
    }

    /// Prohibits generation and execution of dynamic code in writable memory (hardware W^X).
    pub fn prohibit_dynamic_code(mut self) -> Self {
        self.prohibit_dynamic_code = true;
        self
    }

    /// Enables strict OS kernel handle validation.
    ///
    /// # Warning
    ///
    /// On Windows, this sets `RaiseExceptionOnInvalidHandleReference` and `HandleExceptionsPermanentlyEnabled`.
    /// Any subsequent call by the runtime, CRT, or third-party libraries referencing an invalid, stale,
    /// or double-closed handle will raise a fatal kernel exception (`STATUS_INVALID_HANDLE` / `0xC0000008`),
    /// terminating the process immediately.
    pub fn strict_handle_checks(mut self) -> Self {
        self.strict_handle_checks = true;
        self
    }

    /// Hides the calling thread from user-mode debuggers (`ThreadHideFromDebugger`).
    ///
    /// Note: This applies strictly to the currently executing thread. Worker threads or Rayon/Tokio
    /// pools spawned subsequently do not automatically inherit this attribute.
    pub fn hide_current_thread(mut self) -> Self {
        self.hide_current_thread = true;
        self
    }

    /// Disables memory core dump generation on crashes (prevents secret exposure).
    pub fn disable_core_dumps(mut self) -> Self {
        self.disable_core_dumps = true;
        self
    }

    /// Commits and locks the configured safety policies into the OS kernel.
    ///
    /// This should be executed once at the very start of application `main()`.
    ///
    /// # Errors
    ///
    /// Returns `SafetyError::UnsupportedPlatform` if an enabled policy is not supported on the target OS,
    /// unless `.best_effort(true)` was specified.
    pub fn commit(self) -> Result<(), SafetyError> {
        #[cfg(windows)]
        {
            if self.disable_core_dumps && !self.best_effort {
                return Err(SafetyError::UnsupportedPlatform);
            }

            if self.prohibit_dynamic_code {
                os::windows::enforce_prohibit_dynamic_code()?;
            }

            if self.block_unsigned_binaries {
                os::windows::enforce_block_unsigned_binaries()?;
            }

            if self.strict_handle_checks {
                os::windows::enforce_strict_handle_checks()?;
            }

            if self.hide_current_thread {
                os::windows::hide_current_thread()?;
            }
        }

        #[cfg(unix)]
        {
            let has_windows_policies = self.block_unsigned_binaries
                || self.prohibit_dynamic_code
                || self.strict_handle_checks
                || self.hide_current_thread;

            if has_windows_policies && !self.best_effort {
                return Err(SafetyError::UnsupportedPlatform);
            }

            if self.disable_core_dumps {
                os::unix::enforce_disable_dumpable()?;
            }
        }

        #[cfg(not(any(windows, unix)))]
        {
            if !self.best_effort {
                return Err(SafetyError::UnsupportedPlatform);
            }
        }

        Ok(())
    }
}

/// Entrypoint facade for process safety.
pub struct ProcessSafety;

impl ProcessSafety {
    /// Starts configuring a process safety policy.
    pub fn builder() -> ProcessSafetyBuilder {
        ProcessSafetyBuilder::new()
    }
}
