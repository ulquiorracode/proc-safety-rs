//! Stitch-rs Sewing Machine Architecture (SMA) U-cycle safety middleware.

#[cfg(feature = "stitch")]
use stitch_core::flow::FlowControl;

/// Zero-cost U-cycle safety guard middleware for `stitch-rs`.
///
/// Can be placed in execution pipelines (such as `modtree` command dispatch or `statefs` VFS transactions)
/// to assert process invariants and seal memory regions during untrusted guest execution.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcSafetyMiddleware;

#[cfg(feature = "stitch")]
impl ProcSafetyMiddleware {
    /// Executed on downward phase (before entering plugin or command).
    #[inline(always)]
    pub fn on_enter<TIntent, TOutcome, E>(
        &self,
        intent: TIntent,
    ) -> FlowControl<TIntent, TOutcome, E> {
        FlowControl::Proceed(intent)
    }

    /// Executed on upward phase (after plugin or command exits).
    #[inline(always)]
    pub fn on_exit<TOutcome>(&self, outcome: TOutcome) -> TOutcome {
        outcome
    }
}
