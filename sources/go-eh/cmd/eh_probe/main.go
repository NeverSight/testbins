// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT

// Command eh_probe exercises every part of the Go runtime's exceptional
// control flow that NeverD's pclntab decoder claims to recover.
//
// Nothing here is a demonstration program: each function exists to make the
// `gc` toolchain emit one specific piece of runtime metadata, and the shapes
// are chosen so that the two defer lowerings, the explicit and the
// runtime-generated panics, and the recover positions are all separable in
// the linked image.
//
// Constraints the whole file is written under:
//
//   - Standard library only, and as little of it as the behaviour allows,
//     because a Go binary is around a megabyte before it does anything and
//     every extra package is committed corpus weight.  `fmt` alone costs
//     roughly 600 KiB, so output goes through the `println` builtin.
//   - Buildable by every pinned toolchain from Go 1.15 through the current
//     release: no generics, no `any`, no `//go:build` lines, and no reliance
//     on the Go 1.22 per-iteration loop variable, since the module's `go`
//     directive keeps the old semantics.
//   - Every result reaches a package-level sink and every helper is
//     `//go:noinline`, so the linker cannot delete a call site the manifest
//     promises is there.
package main

import (
	"os"
	"runtime"
	"sync"
)

// Sink is written by every probe below.  A package-level variable of a
// non-constant type is the cheapest thing that keeps the whole call graph
// reachable through the linker's dead-code pass.
var Sink int64

// Flags records the boolean outcome of each recovering probe, one bit per
// probe, so that a single observable value depends on all of them.
var Flags uint64

//go:noinline
func consume(v int) int {
	Sink += int64(v)
	return v
}

//go:noinline
func flag(bit uint, ok bool) {
	if ok {
		Flags |= 1 << bit
	}
}

//===========================================================================
// defer + recover in one frame
//===========================================================================

// recoverInPlace is the classic pattern: a single deferred closure that calls
// recover and writes the named result.  One defer, no loop, optimization on,
// so the compiler open-codes it and emits FUNCDATA_OpenCodedDeferInfo plus a
// deferreturn offset in the _func record.
//
//go:noinline
func recoverInPlace(boom bool) (result int) {
	defer func() {
		if v := recover(); v != nil {
			result = -1
		}
	}()
	if boom {
		panic("recoverInPlace")
	}
	result = 1
	return
}

// namedResultRewrite has no panic at all.  It exists so the corpus contains a
// frame whose deferred closure mutates the named result on the normal return
// path, which is the case where deferreturn runs without gopanic ever having
// been entered.
//
//go:noinline
func namedResultRewrite(seed int) (result int) {
	defer func() { result *= 3 }()
	defer func() { result += 7 }()
	result = seed
	return
}

//===========================================================================
// open-coded versus heap-allocated defers
//===========================================================================

// openCodedDefers stays under cmd/compile/internal/walk.maxOpenDefers, which
// is 8 (src/cmd/compile/internal/walk/walk.go), and defers nothing inside a
// loop, so ssagen sets hasOpenDefers and the frame carries a defer bitmask
// instead of any runtime.deferproc call.  The gate is
// `base.Flag.N == 0 && s.hasdefer && !s.curfn.OpenCodedDeferDisallowed()` in
// src/cmd/compile/internal/ssagen/ssa.go, which is why the -N -l cells of
// this corpus contain the same source lowered the other way.
//
//go:noinline
func openCodedDefers(seed int) (result int) {
	defer func() { result += 1 }()
	defer func() { result += 2 }()
	defer func() { result += 4 }()
	defer func() { result += 8 }()
	result = seed
	return
}

// heapDefersInLoop defers inside a loop.  walkStmt marks the function
// OpenCodedDeferDisallowed as soon as a defer escapes, so every iteration
// goes through runtime.deferproc and allocates a _defer record.
//
//go:noinline
func heapDefersInLoop(n int) (result int) {
	for i := 0; i < n; i++ {
		defer func(k int) { result += k }(i)
	}
	return
}

// heapDefersOverThreshold has nine defers, one more than maxOpenDefers, which
// is the other way walkStmt disqualifies a function.  The defers do not
// escape, so these lower to runtime.deferprocStack rather than to
// runtime.deferproc, giving the corpus both heap-defer entry points.
//
//go:noinline
func heapDefersOverThreshold(seed int) (result int) {
	defer func() { result += 1 }()
	defer func() { result += 2 }()
	defer func() { result += 3 }()
	defer func() { result += 4 }()
	defer func() { result += 5 }()
	defer func() { result += 6 }()
	defer func() { result += 7 }()
	defer func() { result += 8 }()
	defer func() { result += 9 }()
	result = seed
	return
}

//===========================================================================
// panic propagation across frames
//===========================================================================

//go:noinline
func deepest(boom bool) int {
	if boom {
		panic("deepest")
	}
	return 3
}

//go:noinline
func middle(boom bool) int { return deepest(boom) + 2 }

//go:noinline
func outer(boom bool) int { return middle(boom) + 1 }

// catchDeep recovers a panic raised three frames below it.  The frames in
// between hold no defer, so the runtime has to unwind past _func records that
// carry no open-coded defer info at all before it reaches this one.
//
//go:noinline
func catchDeep(boom bool) (caught bool) {
	defer func() { caught = recover() != nil }()
	consume(outer(boom))
	return
}

// panicDuringDefer raises a second panic from inside a deferred call while the
// first is still unwinding, then recovers the second.  This is the re-entrant
// path through runtime.gopanic.
//
//go:noinline
func panicDuringDefer() (caught bool) {
	defer func() { caught = recover() != nil }()
	defer func() { panic("raised while unwinding") }()
	panic("original")
}

//===========================================================================
// runtime-generated panics
//===========================================================================

// nilMapWrite faults inside runtime.mapassign, which panics on the runtime's
// own side of the call.  The user frame therefore shows a normal call and the
// panic edge belongs to the runtime function, which is exactly the attribution
// the decoder has to get right.
//
//go:noinline
func nilMapWrite(key string) (caught bool) {
	defer func() { caught = recover() != nil }()
	var m map[string]int
	m[key] = 1
	return
}

// nilPointerDeref faults on the load.  There is no call: the kernel delivers a
// signal and the runtime injects runtime.sigpanic as the faulting frame's
// return address, so this frame's metadata is all the unwinder has.
//
//go:noinline
func nilPointerDeref() (caught bool) {
	defer func() { caught = recover() != nil }()
	var p *int
	consume(*p)
	return
}

// sliceBounds fails a bounds check, which the compiler lowers to an explicit
// branch to one of the runtime.goPanicIndex/runtime.goPanicSlice* helpers, or
// to runtime.panicBounds on Go 1.25 and later where the bounds-failure
// arguments moved into a PCDATA_PanicBounds table.
//
//go:noinline
func sliceBounds(index int) (caught bool) {
	defer func() { caught = recover() != nil }()
	values := make([]int, 3)
	consume(values[index])
	return
}

// sliceExprBounds fails a three-index slice expression, which reaches a
// different helper in the same family than a plain index does.
//
//go:noinline
func sliceExprBounds(high int) (caught bool) {
	defer func() { caught = recover() != nil }()
	values := make([]int, 3, 4)
	consume(len(values[:high]))
	return
}

// divideByZero reaches runtime.panicdivide through a compiler-emitted check.
//
//go:noinline
func divideByZero(divisor int) (caught bool) {
	defer func() { caught = recover() != nil }()
	consume(7 / divisor)
	return
}

// typeAssertion fails a non-comma-ok assertion, which calls one of the
// runtime.panicdottype* helpers.
//
//go:noinline
func typeAssertion(value interface{}) (caught bool) {
	defer func() { caught = recover() != nil }()
	consume(value.(int))
	return
}

//===========================================================================
// goroutines
//===========================================================================

// goroutinePanic recovers a panic raised on a different goroutine.  The
// recovering frame is a deferred closure compiled into a separate function
// whose pclntab name carries the .deferwrap suffix, which is the only thing
// in the image that proves a recover site sits in a deferred frame.
//
//go:noinline
func goroutinePanic() (recovered bool) {
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		defer func() { recovered = recover() != nil }()
		panic("panic on a second goroutine")
	}()
	wait.Wait()
	return
}

// goexitWithDefer terminates a goroutine with runtime.Goexit, which runs the
// frame's defers on the way out without any panic being active.  It is the
// one unwind the runtime performs that gopanic never sees.
//
//go:noinline
func goexitWithDefer() (ranDefer bool) {
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		defer func() { ranDefer = true }()
		runtime.Goexit()
	}()
	wait.Wait()
	return
}

//===========================================================================

//go:noinline
func run() {
	consume(recoverInPlace(true))
	consume(recoverInPlace(false))
	consume(namedResultRewrite(5))
	consume(openCodedDefers(1))
	consume(heapDefersInLoop(4))
	consume(heapDefersOverThreshold(2))

	flag(0, catchDeep(true))
	flag(1, catchDeep(false) == false)
	flag(2, panicDuringDefer())
	flag(3, nilMapWrite("key"))
	flag(4, nilPointerDeref())
	flag(5, sliceBounds(9))
	flag(6, sliceExprBounds(9))
	flag(7, divideByZero(0))
	flag(8, typeAssertion("not an int"))
	flag(9, goroutinePanic())
	flag(10, goexitWithDefer())
}

func main() {
	run()
	println("go-eh eh_probe sink", Sink, "flags", int64(Flags))
	if Flags != 0x7FF {
		os.Exit(1)
	}
}
