# Rust exception probes

Two self-contained crates, no `crates.io` dependencies, compiled by `rustc`
directly rather than through Cargo so that every flag in the manifest is a flag
the producer actually passed.

| Source | Crate | Crate type | Role |
|---|---|---|---|
| `rust_eh_probe.rs` | `rust_eh_probe` | `bin` | Runnable probe; also the corpus's own runtime test |
| `rust_eh_cdylib.rs` | `rust_eh_cdylib` | `cdylib` | The same machinery behind a C ABI boundary |

Both are `std` programs with no `#[panic_handler]` of their own, because that
is what real Rust binaries look like.

## What each construct is for

| Construct | What NeverD recovers from it |
|---|---|
| `Drop` value live across a panicking call | `RustLandingPadKind::DropGlue` |
| `std::panic::catch_unwind` | `RustLandingPadKind::CatchUnwind` (Rust's only catch) |
| `extern "C"` body that can panic | `RustLandingPadKind::NoUnwindGuard` (empty Itanium filter) |
| `extern "C-unwind"` body that can panic | Cleanup only; the panic is allowed through |
| `extern "C"` body that cannot panic | Negative control: no unwind edge at all |
| `panic!` | `RustPanicKind::Explicit` |
| `Option::unwrap` on `None` | `RustPanicKind::Explicit` via `core::option::unwrap_failed` |
| `a + b` under `-C overflow-checks=on` | `RustPanicKind::Arithmetic` via `panic_const_add_overflow` |
| Array index and range slice | `RustPanicKind::BoundsCheck` via `panic_bounds_check` and `slice_index_fail` |

## Rules the sources have to keep

Every probe is `#[inline(never)]` and `#[unsafe(no_mangle)]`, so the manifest
can name it and `-C opt-level=2` cannot rename or merge it, and every
interesting value passes through `std::hint::black_box`, so the optimizer
cannot fold the work away or prove a check unnecessary. `rust_eh_probe`
additionally takes the address of every probe in `anchor_probes`, because
`--gc-sections` would otherwise drop the ones a given build never calls.

The executable never panics under `-C panic=abort`: the raising paths are
behind `cfg(panic = "unwind")`. The same source is therefore an executed
positive control in an unwinding build and a landing-pad-free negative control
in an aborting one.

`scripts/tests/test_rust_sources.py` fails if a probe is added or renamed
without updating the symbol inventory the manifest and verifier share.
