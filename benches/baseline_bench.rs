use criterion::{Criterion, black_box, criterion_group, criterion_main};
use proc_safety::stitch_support::ProcSafetyMiddleware;
use proc_safety::{PageAccess, ProtectedMemory};

fn criterion_benchmark(c: &mut Criterion) {
    let middleware = ProcSafetyMiddleware;

    c.bench_function("proc_safety_u_cycle_middleware_enter", |b| {
        b.iter(|| black_box(middleware.on_enter::<_, (), ()>(black_box(42))))
    });

    c.bench_function("proc_safety_u_cycle_middleware_exit", |b| {
        b.iter(|| black_box(middleware.on_exit(black_box(100))))
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
