// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT

// The C half of the `cgo1` axis.
//
// Setting `CGO_ENABLED=1` on a package that never says `import "C"` changes
// nothing about the link: the go tool has no C to compile, so no C object is
// produced and the image carries no platform unwind table for its own code.
// The axis exists to put a real `.eh_frame` beside Go's `pclntab` and so make
// a decoder choose between them, and this file is what makes that true —
// naming `C` at all is what pulls in `runtime/cgo` and hands the link to a C
// compiler, and the leaf below adds an FDE that describes a frame the Go
// runtime knows nothing about.
//
// No build tag guards this. The go tool excludes a file that imports `C` when
// cgo is off, which is the one form of conditional compilation available to a
// source that must also parse under Go 1.15, before `//go:build` existed.

package main

/*
#include <stdint.h>

// Not a leaf by accident: the recursion gives the unwinder several identical
// C frames to walk, which is what distinguishes an unwind table that was read
// from one that was assumed.
static int64_t eh_probe_c_descend(int64_t depth, int64_t acc) {
	if (depth <= 0) {
		return acc;
	}
	return eh_probe_c_descend(depth - 1, acc * 2 + 1);
}

int64_t eh_probe_c_entry(int64_t depth) {
	return eh_probe_c_descend(depth, 1);
}
*/
import "C"

// CgoSink is deliberately separate from Sink: the pure-Go probes assert an
// exact sink value against themselves, and a cgo build must not move it.
var CgoSink int64

func init() {
	CgoSink = int64(C.eh_probe_c_entry(C.int64_t(6)))
}
