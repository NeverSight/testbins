// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT

//! Executable probe for the NeverD Rust exception corpus.
//!
//! Every construct here exists because a NeverD decoder reads it back out of
//! the produced image:
//!
//! * a value with a `Drop` impl held across a call that panics, so the frame
//!   carries a real cleanup landing pad (`RustLandingPadKind::DropGlue`);
//! * `std::panic::catch_unwind`, which is the only place Rust emits a catch
//!   (`RustLandingPadKind::CatchUnwind`);
//! * an `extern "C"` function whose body can panic, which rustc wraps in the
//!   abort-on-unwind guard spelled as an empty Itanium filter
//!   (`RustLandingPadKind::NoUnwindGuard`), next to the `extern "C-unwind"`
//!   function that is allowed to let the panic through;
//! * one call site per distinct `core::panicking` entry point, so the panic
//!   site classifier has an Explicit, a BoundsCheck, and an Arithmetic edge to
//!   find.
//!
//! Two rules keep those constructs in the binary at `-C opt-level=2`. Every
//! probe is `#[inline(never)]` and `#[unsafe(no_mangle)]`, so the manifest can
//! name it and the linker cannot rename it; and every interesting value passes
//! through `std::hint::black_box`, so the optimizer cannot fold the work away
//! or prove a check unnecessary.
//!
//! The program is also its own runtime test, and it must stay runnable under
//! both panic strategies. The paths that actually raise are behind
//! `cfg(panic = "unwind")`: the same source is an executed positive control in
//! an unwinding build and a landing-pad-free negative control in an aborting
//! one.

use std::hint::black_box;
use std::panic::{self, AssertUnwindSafe};
use std::process::ExitCode;
use std::sync::atomic::{AtomicI64, Ordering};

/// Argument value that makes a probe panic. It is only ever passed through
/// `black_box`, so no probe can be specialized into its panicking half.
const PANIC_TRIGGER: i64 = 7;

/// Argument value that makes a probe return normally.
const QUIET_VALUE: i64 = 3;

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

/// A call the optimizer cannot see through. Every caller has to assume it
/// unwinds, which is what puts a cleanup edge on the caller's live values.
#[inline(never)]
fn raise_when(trigger: i64, label: &'static str) -> i64 {
    if black_box(trigger) == PANIC_TRIGGER {
        panic!("rust-eh probe: {label}");
    }
    black_box(trigger)
}

/// One live `Drop` value across one panicking call: the smallest frame that
/// carries drop glue.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn rust_eh_drop_across_panic(trigger: i64) -> i64 {
    let held = DropCounter::new(1);
    let value = raise_when(trigger, "drop across panic");
    black_box(value) + black_box(held.weight)
}

/// Three nested scopes, each with its own live `Drop` value, so the cleanup
/// actions have an order for a decoder to recover.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn rust_eh_nested_drop_order(trigger: i64) -> i64 {
    let outer = DropCounter::new(100);
    let mut total = 0;
    {
        let middle = DropCounter::new(20);
        {
            let inner = DropCounter::new(3);
            total += raise_when(trigger, "nested drop order");
            total += black_box(inner.weight);
        }
        total += black_box(middle.weight);
    }
    total + black_box(outer.weight)
}

/// The only construct in Rust that emits a catch clause. A live `Drop` value
/// sits beside it so the frame carries cleanup and a catch at once.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn rust_eh_catch_unwind_boundary(trigger: i64) -> i64 {
    let held = DropCounter::new(7);
    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
        raise_when(trigger, "catch_unwind boundary")
    }));
    let outcome = match caught {
        Ok(value) => value,
        Err(_) => -1,
    };
    black_box(outcome) + black_box(held.weight)
}

/// `core::panicking::panic` / `panic_fmt`: classified as an explicit panic.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn rust_eh_explicit_panic(trigger: i64) -> i64 {
    if black_box(trigger) == PANIC_TRIGGER {
        panic!("rust-eh probe: explicit panic");
    }
    black_box(trigger)
}

/// `core::panicking::panic_const::panic_const_add_overflow`: classified as an
/// arithmetic panic. The producer passes `-C overflow-checks=on` so this edge
/// exists at every optimization level rather than only at `-C opt-level=0`.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn rust_eh_overflow_panic(left: i32, right: i32) -> i32 {
    black_box(left) + black_box(right)
}

/// `core::panicking::panic_bounds_check`: classified as a bounds-check panic.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn rust_eh_index_panic(index: usize) -> i64 {
    let values: [i64; 4] = [black_box(2), 3, 5, 7];
    black_box(values[black_box(index)])
}

/// `core::slice::index::slice_*_fail`: the range-slicing half of the
/// bounds-check family, which has its own runtime entry points.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn rust_eh_slice_range_panic(start: usize, end: usize) -> i64 {
    let values: [i64; 4] = [black_box(2), 3, 5, 7];
    let window = &values[black_box(start)..black_box(end)];
    black_box(window.iter().sum())
}

/// `core::option::Option::unwrap` on `None`, which reaches
/// `core::panicking::unwrap_failed` rather than `panic` directly.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn rust_eh_unwrap_none_panic(present: bool) -> i64 {
    let value: Option<i64> = if black_box(present) {
        Some(black_box(11))
    } else {
        None
    };
    black_box(value.unwrap())
}

/// `extern "C-unwind"`: a panic is allowed to leave this frame, so it carries
/// ordinary drop glue and no abort guard.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn rust_eh_c_unwind_boundary(trigger: i64) -> i64 {
    let held = DropCounter::new(13);
    let value = raise_when(trigger, "extern C-unwind boundary");
    black_box(value) + black_box(held.weight)
}

/// `extern "C"`: a panic must not leave this frame. rustc wraps the body in the
/// abort-on-unwind guard, which on an Itanium target is an empty filter and on
/// MSVC is a funclet that calls `panic_cannot_unwind`.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_c_abort_boundary(trigger: i64) -> i64 {
    let held = DropCounter::new(17);
    let value = raise_when(trigger, "extern C abort boundary");
    black_box(value) + black_box(held.weight)
}

/// `extern "C"` whose body provably cannot panic: the negative control for the
/// guard above, and the one exported function that needs no unwind edge at all.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_c_leaf_nounwind(value: i64) -> i64 {
    black_box(value).wrapping_mul(3)
}

/// Addresses of every probe, so `--gc-sections` cannot drop the ones this
/// build never calls.
fn anchor_probes() {
    let anchors: [*const (); 11] = [
        rust_eh_drop_across_panic as *const (),
        rust_eh_nested_drop_order as *const (),
        rust_eh_catch_unwind_boundary as *const (),
        rust_eh_explicit_panic as *const (),
        rust_eh_overflow_panic as *const (),
        rust_eh_index_panic as *const (),
        rust_eh_slice_range_panic as *const (),
        rust_eh_unwrap_none_panic as *const (),
        rust_eh_c_unwind_boundary as *const (),
        rust_eh_c_abort_boundary as *const (),
        rust_eh_c_leaf_nounwind as *const (),
    ];
    black_box(&anchors);
}

/// The paths that return normally. Safe to run under either panic strategy.
fn run_quiet_paths() -> i64 {
    let mut total = 0;
    total += rust_eh_drop_across_panic(QUIET_VALUE);
    total += rust_eh_nested_drop_order(QUIET_VALUE);
    total += rust_eh_catch_unwind_boundary(QUIET_VALUE);
    total += rust_eh_explicit_panic(QUIET_VALUE);
    total += i64::from(rust_eh_overflow_panic(2, 3));
    total += rust_eh_index_panic(2);
    total += rust_eh_slice_range_panic(1, 3);
    total += rust_eh_unwrap_none_panic(true);
    total += rust_eh_c_unwind_boundary(QUIET_VALUE);
    total += rust_eh_c_abort_boundary(QUIET_VALUE);
    total += rust_eh_c_leaf_nounwind(5);
    total
}

/// The paths that raise. An aborting build has no way to observe these without
/// ending the process, so it does not run them.
#[cfg(panic = "unwind")]
fn run_unwinding_paths() -> Result<(), String> {
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    DROP_LOG.store(0, Ordering::SeqCst);
    let caught = panic::catch_unwind(|| rust_eh_drop_across_panic(PANIC_TRIGGER));
    let dropped_across_panic = DROP_LOG.load(Ordering::SeqCst);

    DROP_LOG.store(0, Ordering::SeqCst);
    let nested = panic::catch_unwind(|| rust_eh_nested_drop_order(PANIC_TRIGGER));
    let dropped_nested = DROP_LOG.load(Ordering::SeqCst);

    DROP_LOG.store(0, Ordering::SeqCst);
    let recovered = rust_eh_catch_unwind_boundary(PANIC_TRIGGER);

    let indexed = panic::catch_unwind(|| rust_eh_index_panic(9));
    let ranged = panic::catch_unwind(|| rust_eh_slice_range_panic(3, 1));
    let unwrapped = panic::catch_unwind(|| rust_eh_unwrap_none_panic(false));
    let overflowed = panic::catch_unwind(|| rust_eh_overflow_panic(i32::MAX, 1));
    let crossed = panic::catch_unwind(|| rust_eh_c_unwind_boundary(PANIC_TRIGGER));

    panic::set_hook(previous_hook);

    if caught.is_ok() {
        return Err("drop-across-panic probe did not panic".to_owned());
    }
    if dropped_across_panic != 1 {
        return Err(format!(
            "drop-across-panic ran {dropped_across_panic} of 1 drop"
        ));
    }
    if nested.is_ok() {
        return Err("nested-drop-order probe did not panic".to_owned());
    }
    if dropped_nested != 123 {
        return Err(format!("nested drop order summed to {dropped_nested}, want 123"));
    }
    if recovered != 6 {
        return Err(format!("catch_unwind probe returned {recovered}, want 6"));
    }
    if indexed.is_ok() || ranged.is_ok() || unwrapped.is_ok() {
        return Err("a checked-access probe did not panic".to_owned());
    }
    if overflowed.is_ok() {
        return Err("the overflow probe did not panic; -C overflow-checks=on is required".to_owned());
    }
    if crossed.is_ok() {
        return Err("the extern \"C-unwind\" probe did not let the panic through".to_owned());
    }
    Ok(())
}

#[cfg(not(panic = "unwind"))]
fn run_unwinding_paths() -> Result<(), String> {
    Ok(())
}

fn main() -> ExitCode {
    anchor_probes();
    let quiet = run_quiet_paths();
    if quiet != 223 {
        eprintln!("rust-eh probe failed: quiet paths summed to {quiet}, want 223");
        return ExitCode::FAILURE;
    }
    if let Err(reason) = run_unwinding_paths() {
        eprintln!("rust-eh probe failed: {reason}");
        return ExitCode::FAILURE;
    }
    println!("rust-eh probe passed");
    ExitCode::SUCCESS
}
