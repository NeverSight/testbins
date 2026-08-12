// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT

//! Shared-library half of the NeverD Rust exception corpus.
//!
//! A `cdylib` is where Rust's unwind edges meet a foreign caller, so it is the
//! build that makes the `extern "C"` / `extern "C-unwind"` distinction load
//! bearing rather than academic. The same panic machinery as the executable
//! probe is reachable here, but every entry point is a C-ABI export, which puts
//! the abort-on-unwind guard on the boundary a decompiler actually sees first.
//!
//! There is deliberately no `main` and no dependency on `std::process`: this
//! crate is loaded, not run, and the corpus records it as such.

use std::hint::black_box;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicI64, Ordering};

/// Argument value that makes an export panic.
const PANIC_TRIGGER: i64 = 7;

static DROP_LOG: AtomicI64 = AtomicI64::new(0);

/// Gives a cleanup landing pad observable work, so the pad cannot be discarded
/// as empty.
struct DropCounter {
    weight: i64,
}

impl DropCounter {
    fn new(weight: i64) -> Self {
        DropCounter {
            weight: black_box(weight),
        }
    }
}

impl Drop for DropCounter {
    fn drop(&mut self) {
        DROP_LOG.fetch_add(self.weight, Ordering::SeqCst);
    }
}

/// A call the optimizer cannot see through, so every caller keeps a cleanup
/// edge around it.
#[inline(never)]
fn raise_when(trigger: i64, label: &'static str) -> i64 {
    if black_box(trigger) == PANIC_TRIGGER {
        panic!("rust-eh cdylib: {label}");
    }
    black_box(trigger)
}

/// `extern "C-unwind"`: the panic is allowed to leave the library and reach the
/// foreign caller, so this frame carries drop glue and no guard.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn rust_eh_dylib_c_unwind_boundary(trigger: i64) -> i64 {
    let held = DropCounter::new(13);
    let value = raise_when(trigger, "extern C-unwind export");
    black_box(value) + black_box(held.weight)
}

/// `extern "C"`: the panic must not leave the library. rustc wraps the body in
/// the abort-on-unwind guard, which is the construct NeverD reports as
/// `RustLandingPadKind::NoUnwindGuard`.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_dylib_c_abort_boundary(trigger: i64) -> i64 {
    let held = DropCounter::new(17);
    let value = raise_when(trigger, "extern C export");
    black_box(value) + black_box(held.weight)
}

/// The recommended shape for a C-ABI export: catch the panic inside the library
/// and report it as a return value. It is also the only place a `cdylib` emits
/// a genuine catch clause.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_dylib_catch_unwind_boundary(trigger: i64) -> i64 {
    let held = DropCounter::new(7);
    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
        raise_when(trigger, "catch_unwind export")
    }));
    let outcome = match caught {
        Ok(value) => value,
        Err(_) => -1,
    };
    black_box(outcome) + black_box(held.weight)
}

/// Nested `Drop` scopes behind a C-ABI export, so the guarded frame also has
/// cleanup actions with an order.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_dylib_nested_drop_order(trigger: i64) -> i64 {
    let outer = DropCounter::new(100);
    let mut total = 0;
    {
        let inner = DropCounter::new(3);
        total += raise_when(trigger, "nested drop export");
        total += black_box(inner.weight);
    }
    total + black_box(outer.weight)
}

/// `core::panicking::panic_bounds_check` behind a C-ABI export.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_dylib_index_panic(index: usize) -> i64 {
    let values: [i64; 4] = [black_box(2), 3, 5, 7];
    black_box(values[black_box(index)])
}

/// `extern "C"` whose body provably cannot panic: the negative control for the
/// guard, and the export a foreign caller can rely on unconditionally.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_dylib_c_leaf_nounwind(value: i64) -> i64 {
    black_box(value).wrapping_mul(3)
}

/// Total weight of the `Drop` impls this library has run, so a loader can
/// confirm the cleanup paths executed rather than being optimized away.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_dylib_drop_log() -> i64 {
    DROP_LOG.load(Ordering::SeqCst)
}
