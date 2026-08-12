# go-eh probe sources

One module, no dependencies, one command. `cmd/eh_probe` exists to make the
`gc` toolchain emit every piece of runtime metadata NeverD's `pclntab` decoder
claims to read, and to prove at run time that the metadata it emitted actually
drove the unwinds it describes.

## Why one program and not a suite

A Go binary is roughly a megabyte before it does anything, and this corpus is
committed to a repository other projects clone as a submodule. Every artifact
therefore contains the same program, and the axes that vary are the ones that
change the metadata rather than the code: the toolchain release, the container,
the link mode, and the optimization mode. Twenty-three images of one program
cost a third of what a handful of programs across the same axes would.

The program uses only `os`, `runtime`, and `sync`. `fmt` alone would add about
600 KiB to every artifact, so output goes through the `println` builtin.

## What each function pins

| Function | Metadata it forces |
|---|---|
| `recoverInPlace` | one open-coded defer, a recover in the deferring frame, a `deferreturn` offset |
| `namedResultRewrite` | a deferred closure that rewrites a named result on the normal return path |
| `openCodedDefers` | four defers, no loop: `FUNCDATA_OpenCodedDeferInfo` with several slots |
| `heapDefersInLoop` | a defer that escapes, so `runtime.deferproc` and a heap `_defer` |
| `heapDefersOverThreshold` | nine defers, one over `walk.maxOpenDefers`, so `runtime.deferprocStack` |
| `deepest` / `middle` / `outer` / `catchDeep` | a panic unwound across three frames that hold no defer |
| `panicDuringDefer` | a second panic raised while the first unwinds, re-entering `runtime.gopanic` |
| `nilMapWrite` | a panic raised inside `runtime.mapassign` rather than at the user call site |
| `nilPointerDeref` | a fault, so `runtime.sigpanic` is injected instead of called |
| `sliceBounds` / `sliceExprBounds` | compiler-emitted branches to the bounds-failure helpers |
| `divideByZero` | `runtime.panicdivide` |
| `typeAssertion` | `runtime.panicdottype*` |
| `goroutinePanic` | a recover on a second goroutine, inside a `.deferwrap` frame |
| `goexitWithDefer` | `runtime.Goexit`, the one unwind that runs defers with no panic active |

`maxOpenDefers` is 8, from `src/cmd/compile/internal/walk/walk.go`. Open coding
is gated on `base.Flag.N == 0 && s.hasdefer && !s.curfn.OpenCodedDeferDisallowed()`
in `src/cmd/compile/internal/ssagen/ssa.go`, which is why the corpus carries a
`-gcflags=all=-N -l` cell: it contains the same source with every defer lowered
to a runtime call instead.

## Constraints on edits

- Standard library only, and as little of it as the behaviour allows.
- Buildable by every pinned toolchain, currently Go 1.15.15 through Go 1.26.5.
  That rules out generics, `any`, `min`/`max`, and `//go:build` lines, and it
  rules out depending on the Go 1.22 per-iteration loop variable, because the
  module's `go` directive keeps the older semantics.
- Every helper keeps its `//go:noinline` and every result reaches `Sink` or
  `Flags`. A helper the linker deletes is an artifact that quietly stops
  containing the thing it was added for.
- `run` sets one bit per recovering probe and `main` exits non-zero unless all
  of them are set, so the host-native cells fail the build rather than
  publishing an image whose metadata did not work.

`scripts/tests/test_go_sources.py` enforces these properties.
