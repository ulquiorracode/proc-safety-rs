//! Error types for process safety and memory boundary operations.

use thiserror::Error;

/// Errors returned by process mitigation and memory boundary operations.
#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("OS kernel rejected mitigation policy: system error code {0}")]
    OsPolicyRejection(u32),

    #[error("failed to query or modify thread protection flags: system error code {0}")]
    ThreadProtectionFailed(u32),

    #[error("failed to adjust memory page protection: system error code {0}")]
    PageProtectionFailed(u32),

    #[error("operation not supported on target platform")]
    UnsupportedPlatform,

    #[error("safety policy violation: {0}")]
    Violation(String),
}
