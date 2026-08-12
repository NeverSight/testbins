/* Copyright (c) NeverSight contributors.
 * SPDX-License-Identifier: MIT
 *
 * C half of the NeverD C++ Itanium exception corpus.
 *
 * A C translation unit compiled with `-fexceptions` produces the one Itanium
 * table shape the C++ probes never produce: a language specific data area with
 * a call-site table, cleanup actions, and no type table at all, reached through
 * `__gcc_personality_v0` instead of `__gxx_personality_v0`.  Every real program
 * that mixes C and C++ has frames like these, and a decoder that only ever sees
 * `__gxx_personality_v0` mis-reads them as having an empty catch list rather
 * than no catch list.
 *
 * The cleanup edges only exist because something on the other side of a call
 * can actually unwind, so this file links against `libcxx_eh_shared` and lets a
 * C++ exception travel through its frames.  `cxx_eh_shared_call_and_catch`
 * closes the loop: C++ calls C, C calls back into C++, and the throw crosses
 * the C frame on its way to a C++ catch.
 */

#include <stdio.h>

#if defined(_WIN32)
#define CXX_EH_SHARED_IMPORT __declspec(dllimport)
#else
#define CXX_EH_SHARED_IMPORT
#endif

CXX_EH_SHARED_IMPORT long cxx_eh_shared_raise(long trigger);
CXX_EH_SHARED_IMPORT long cxx_eh_shared_catch(long trigger);
CXX_EH_SHARED_IMPORT long cxx_eh_shared_call_and_catch(long (*callback)(long),
                                                       long trigger);
CXX_EH_SHARED_IMPORT long cxx_eh_shared_log(void);

/* The argument that makes the C++ library throw. */
#define C_EH_THROW_TRIGGER 7

/* The argument that makes it return normally. */
#define C_EH_QUIET_VALUE 3

static long g_c_cleanup_log;

static long opaque(long value) {
  __asm__ volatile("" : "+r"(value) : : "memory");
  return value;
}

/* Gives the cleanup action observable work, so it cannot be discarded. */
static void c_eh_note(long *slot) { g_c_cleanup_log += *slot; }

/* One cleanup variable across a call that can unwind: the smallest C frame
 * that carries a `__gcc_personality_v0` table. */
__attribute__((noinline)) long c_eh_probe_cleanup_only(long trigger) {
  long guard __attribute__((cleanup(c_eh_note))) = opaque(1);
  return cxx_eh_shared_catch(trigger) + opaque(guard);
}

/* Two cleanup variables in nested scopes, so the call-site table has more than
 * one region and the action chain has an order. */
__attribute__((noinline)) long c_eh_probe_nested_cleanup(long trigger) {
  long outer __attribute__((cleanup(c_eh_note))) = opaque(2);
  long total = 0;
  {
    long inner __attribute__((cleanup(c_eh_note))) = opaque(4);
    total += cxx_eh_shared_catch(trigger) + opaque(inner);
  }
  return total + opaque(outer);
}

/* The frame a C++ exception actually travels through.  It is reached from
 * `cxx_eh_shared_call_and_catch`, so the throw below it and the catch above it
 * are both in the shared library and this frame only has to resume. */
__attribute__((noinline)) long c_eh_probe_raise_bridge(long trigger) {
  long guard __attribute__((cleanup(c_eh_note))) = opaque(8);
  return cxx_eh_shared_raise(trigger) + opaque(guard);
}

/* Drives the round trip: C++ -> C -> C++ throw -> C unwind -> C++ catch. */
__attribute__((noinline)) long c_eh_probe_cross_frame(long trigger) {
  return cxx_eh_shared_call_and_catch(c_eh_probe_raise_bridge, trigger);
}

int main(void) {
  long before;
  long crossed;

  if (c_eh_probe_cleanup_only(C_EH_QUIET_VALUE) < 1) {
    fprintf(stderr, "cxx-itanium-eh probe failed: the cleanup-only C frame\n");
    return 1;
  }
  if (c_eh_probe_nested_cleanup(C_EH_QUIET_VALUE) < 1) {
    fprintf(stderr, "cxx-itanium-eh probe failed: the nested C cleanups\n");
    return 1;
  }
  if (c_eh_probe_cross_frame(C_EH_QUIET_VALUE) < 1) {
    fprintf(stderr, "cxx-itanium-eh probe failed: the quiet round trip\n");
    return 1;
  }

  /* The exception is raised and caught inside the shared library, so it is
   * safe to run: what has to survive is this file's C frame in between. */
  before = g_c_cleanup_log;
  crossed = c_eh_probe_cross_frame(C_EH_THROW_TRIGGER);
  if (crossed != -31) {
    fprintf(stderr,
            "cxx-itanium-eh probe failed: the C++ catch returned %ld\n",
            crossed);
    return 1;
  }
  if (g_c_cleanup_log <= before) {
    fprintf(stderr,
            "cxx-itanium-eh probe failed: the C cleanup did not run while "
            "unwinding\n");
    return 1;
  }
  if (cxx_eh_shared_log() < 1) {
    fprintf(stderr,
            "cxx-itanium-eh probe failed: the library ran no destructors\n");
    return 1;
  }

  puts("cxx-itanium-eh probe passed");
  return 0;
}
