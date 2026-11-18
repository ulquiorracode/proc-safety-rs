use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use proc_safety::stitch_support::ProcSafetyMiddleware;
use proc_safety::{PageAccess, ProtectedMemory};
use stitch_core::middleware::Layer;

fn criterion_benchmark(c: &mut Criterion) {
    let middleware = ProcSafetyMiddleware;

    c.bench_function("proc_safety_u_cycle_middleware_enter", |b| {
        let mut ctx = ();
        b.iter(|| {
            black_box(Layer::<(), i32, (), ()>::on_enter(
                &middleware,
                &mut ctx,
                black_box(42),
            ))
        })
    });

    c.bench_function("proc_safety_u_cycle_middleware_exit", |b| {
        let mut ctx = ();
        let mut outcome: Result<i32, ()> = Ok(100);
        b.iter(|| {
            Layer::<(), i32, i32, ()>::on_exit(&middleware, &mut ctx, black_box(&mut outcome));
            black_box(outcome)
        })
    });

    let mut mem = ProtectedMemory::allocate(64).expect("mem alloc failed");
    c.bench_function("proc_safety_memory_protect_roundtrip", |b| {
        b.iter(|| {
            mem.protect(PageAccess::ReadOnly).unwrap();
            black_box(mem.as_slice().unwrap());
            mem.protect(PageAccess::ReadWrite).unwrap();
            black_box(mem.as_mut_slice().unwrap());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
