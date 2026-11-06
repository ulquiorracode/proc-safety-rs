# proc-safety-rs

> **Zero-cost, internal process self-defense, memory boundaries, and OS kernel mitigation policies for native Rust processes.**

`proc-safety-rs` hardens running processes directly from the inside without requiring external containers, hypervisors, or heavyweight virtualization. It interfaces directly with OS kernel mitigations (Windows Process Mitigations and Linux `prctl`/`seccomp`) and provides zero-overhead memory protection barriers.

## Capabilities

- **Zero Runtime Overhead**: Policies are committed to the OS kernel once at startup; verification is handled by hardware CPU/MMU paging structures.
- **DLL Injection Wall**: Blocks unsigned module loading via Windows `SignaturePolicy` (`Microsoft-signed only`).
- **Dynamic Code Prevention**: Enforces hardware W^X (Write XOR Execute) to prohibit executable page allocations in heaps/stacks.
- **Thread Camouflage**: Hides sensitive game, networking, or crypto threads from user-mode debuggers (`ThreadHideFromDebugger`).
- **Memory Boundaries**: Locks critical pages into `PAGE_READONLY` or arms tripwire detection via `PAGE_GUARD`.
- **Ecosystem Glue**: Seamlessly integrates into `stitch-rs` pipelines, providing defensive SMA middlewares for `modtree` and `statefs`.

## Quick Start

```rust
use proc_safety::ProcessSafety;

fn main() {
    // Commit process armor on startup before spawning untrusted plugins or threads
    ProcessSafety::builder()
        .block_unsigned_binaries()
        .prohibit_dynamic_code()
        .strict_handle_checks()
        .hide_current_thread()
        .commit()
        .expect("failed to apply kernel safety policy");
}
```
