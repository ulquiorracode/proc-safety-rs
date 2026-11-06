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
}

impl ProcessSafetyBuilder {
    /// Creates a new uncommitted process safety builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Blocks loading of unsigned third-party dynamic libraries.
    pub fn block_unsigned_binaries(mut self) -> Self {
        self.block_unsigned_binaries = true;
        self
    }

    /// Prohibits generation and execution of dynamic code in writable memory (W^X).
    pub fn prohibit_dynamic_code(mut self) -> Self {
        self.prohibit_dynamic_code = true;
        self
    }

    /// Enables strict OS kernel handle validation (immediate crash on invalid handles).
    pub fn strict_handle_checks(mut self) -> Self {
        self.strict_handle_checks = true;
        self
    }

    /// Hides the calling thread from user-mode debuggers.
    pub fn hide_current_thread(mut self) -> Self {
        self.hide_current_thread = true;
        self
    }

    /// Disables memory core dump generation on crashes (prevents secret leaks).
    pub fn disable_core_dumps(mut self) -> Self {
        self.disable_core_dumps = true;
        self
    }

    /// Commits and locks the configured safety policies into the OS kernel.
    ///
    /// This should be executed once at the very start of the application `main()`.
    pub fn commit(self) -> Result<(), SafetyError> {
        #[cfg(windows)]
        {
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
            if self.disable_core_dumps {
                os::unix::enforce_disable_dumpable()?;
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
