// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT
//
// Executable probe for the NeverD C++ Itanium exception corpus.
//
// Every construct here exists because a NeverD decoder reads it back out of
// the produced image.  The Itanium C++ ABI puts all of it in one language
// specific data area per function -- a call-site table, an action chain, and a
// type table -- so the probe's job is to make every shape of that table appear
// at once:
//
//   * catch by value, by const reference, and by pointer, which differ in how
//     the type table entry is matched and in what `__cxa_begin_catch` hands
//     over;
//   * one try with four catch clauses, so the type table has an order and the
//     action chain has more than one link;
//   * `catch (...)`, which is the catch-all entry the ABI spells as type index
//     zero;
//   * a bare `throw;`, which is `__cxa_rethrow` and not a second `__cxa_throw`;
//   * locals with non-trivial destructors, singly and as arrays, so cleanup-only
//     call-site records exist beside the catching ones;
//   * a base catch for a derived throw, and the same through virtual
//     inheritance, where the runtime has to adjust the object pointer;
//   * a `noexcept` body that can throw, which is the terminate landing pad
//     rather than a catch;
//   * a function-scope static whose initializer can throw, which is the only
//     construct that reaches `__cxa_guard_abort`.
//
// Two rules keep those constructs in the image at `-O2`.  Every probe is
// `extern "C"` and `noinline`, so the manifest can name it and the optimizer
// cannot merge or rename it; and every interesting value passes through
// `opaque`, so the optimizer cannot fold the work away or prove a throw
// unreachable.
//
// The same source is also the corpus's negative control, because it has to
// compile with `-fno-exceptions`.  Everything that raises -- including the
// exception types themselves -- lives behind `CXX_EH_PROBE_EXCEPTIONS`, so an
// exception-free build of this file is a program with the same entry points,
// the same destructor work, and no landing pad anywhere.

#include <atomic>
#include <cstdio>

#if defined(__cpp_exceptions) && __cpp_exceptions
#define CXX_EH_PROBE_EXCEPTIONS 1
#else
#define CXX_EH_PROBE_EXCEPTIONS 0
#endif

#if CXX_EH_PROBE_EXCEPTIONS
#include <functional>
#include <stdexcept>
#endif

namespace {

/// Argument value that makes a probe throw.  It only ever reaches a probe
/// through `opaque`, so no probe can be specialized into its throwing half.
constexpr long kThrowTrigger = 7;

/// Argument value that makes a probe return normally.
constexpr long kQuietValue = 3;

std::atomic<long> g_cleanup_log{0};

/// A value the optimizer cannot see through.
long opaque(long value) {
  __asm__ volatile("" : "+r"(value) : : "memory");
  return value;
}

/// The same for an address, which `long` cannot hold on every target this
/// corpus builds for.
const void *opaque_pointer(const void *value) {
  __asm__ volatile("" : "+r"(value) : : "memory");
  return value;
}

/// Gives a cleanup action observable work, so a landing pad that runs it
/// cannot be discarded as empty.
struct CleanupCounter {
  explicit CleanupCounter(long weight) : weight(opaque(weight)) {}
  ~CleanupCounter() {
    g_cleanup_log.fetch_add(weight, std::memory_order_seq_cst);
  }

  long weight;
};

}  // namespace

//
// Probes that exist in every build.  Nothing here raises, so an exception-free
// compilation still produces a program with the same entry points and the same
// destructor work.
//

extern "C" __attribute__((noinline)) long cxx_eh_probe_quiet_sum(long value) {
  return opaque(value) * 3 + opaque(1);
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_cleanup_scope(long value) {
  CleanupCounter held(1);
  return opaque(value) + opaque(held.weight);
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_array_scope(long value) {
  CleanupCounter batch[3] = {CleanupCounter(2), CleanupCounter(3),
                             CleanupCounter(5)};
  return opaque(value) + opaque(batch[0].weight) + opaque(batch[2].weight);
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_loop_scope(long value) {
  long total = 0;
  for (long index = 0; index < opaque(3); ++index) {
    CleanupCounter step(index + 1);
    total += opaque(step.weight);
  }
  return total + opaque(value);
}

#if CXX_EH_PROBE_EXCEPTIONS

/// The custom exception type.  Its mangled name is the one piece of C++
/// identity that survives stripping, so the manifest asserts the byte string
/// `15CxxEhProbeError` and `scripts/tests/test_cxx_itanium_sources.py` fails if
/// the class is renamed without the contract following it.
struct CxxEhProbeError {
  explicit CxxEhProbeError(long value) : code(value) {}
  virtual ~CxxEhProbeError();

  long code;
};

CxxEhProbeError::~CxxEhProbeError() = default;

/// A derived throw caught by its base, where the runtime adjusts the object
/// pointer by a constant offset.
struct CxxEhProbeDerivedError : CxxEhProbeError {
  explicit CxxEhProbeDerivedError(long value)
      : CxxEhProbeError(value), detail(value * 2) {}
  ~CxxEhProbeDerivedError() override;

  long detail;
};

CxxEhProbeDerivedError::~CxxEhProbeDerivedError() = default;

/// The same base catch through a virtual base, where the adjustment is a
/// lookup rather than a constant.
struct CxxEhProbeVirtualBase {
  virtual ~CxxEhProbeVirtualBase();

  long tag = 0;
};

CxxEhProbeVirtualBase::~CxxEhProbeVirtualBase() = default;

struct CxxEhProbeVirtualLeft : virtual CxxEhProbeVirtualBase {};
struct CxxEhProbeVirtualRight : virtual CxxEhProbeVirtualBase {};

struct CxxEhProbeVirtualDiamond : CxxEhProbeVirtualLeft,
                                  CxxEhProbeVirtualRight {
  explicit CxxEhProbeVirtualDiamond(long value) { tag = value; }
  ~CxxEhProbeVirtualDiamond() override;
};

CxxEhProbeVirtualDiamond::~CxxEhProbeVirtualDiamond() = default;

namespace {

/// A call the optimizer cannot see through.  Every caller has to assume it
/// throws, which is what puts a cleanup edge on the caller's live values.
[[gnu::noinline]] long raise_when(long trigger, long code) {
  if (opaque(trigger) == kThrowTrigger) {
    throw CxxEhProbeError(code);
  }
  return opaque(trigger);
}

[[gnu::noinline]] long raise_int_when(long trigger, long code) {
  if (opaque(trigger) == kThrowTrigger) {
    throw static_cast<int>(code);
  }
  return opaque(trigger);
}

CxxEhProbeError g_pointer_exception(41);

/// A static local whose initializer can throw.
struct GuardedInitializer {
  explicit GuardedInitializer(long trigger) : value(raise_when(trigger, 25)) {}

  long value;
};

[[gnu::noinline]] long propagate_level_two(long trigger) {
  CleanupCounter held(16);
  return raise_when(trigger, 16) + opaque(held.weight);
}

[[gnu::noinline]] long propagate_level_one(long trigger) {
  CleanupCounter held(17);
  return propagate_level_two(trigger) + opaque(held.weight);
}

}  // namespace

extern "C" __attribute__((noinline)) long cxx_eh_probe_catch_by_value(
    long trigger) {
  try {
    return raise_int_when(trigger, 5);
  } catch (int caught) {
    return -static_cast<long>(caught);
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_catch_by_reference(
    long trigger) {
  try {
    return raise_when(trigger, 6);
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_catch_by_pointer(
    long trigger) {
  try {
    if (opaque(trigger) == kThrowTrigger) {
      throw &g_pointer_exception;
    }
    return opaque(trigger);
  } catch (CxxEhProbeError *caught) {
    return -caught->code;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_catch_ellipsis(
    long trigger) {
  try {
    return raise_when(trigger, 8);
  } catch (...) {
    return -8;
  }
}

/// Four clauses on one try, so the type table has an order a decoder has to
/// preserve and the action chain has more than one link.
extern "C" __attribute__((noinline)) long cxx_eh_probe_catch_ladder(
    long trigger) {
  try {
    if (opaque(trigger) == kThrowTrigger) {
      throw std::runtime_error("cxx-itanium-eh probe: catch ladder");
    }
    return raise_when(trigger, 9);
  } catch (int caught) {
    return -static_cast<long>(caught);
  } catch (const CxxEhProbeDerivedError &caught) {
    return -caught.detail;
  } catch (const std::runtime_error &) {
    return -91;
  } catch (...) {
    return -92;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_nested_try(
    long trigger) {
  CleanupCounter outer(10);
  try {
    CleanupCounter middle(20);
    try {
      CleanupCounter inner(30);
      return raise_when(trigger, 10) + opaque(inner.weight);
    } catch (const CxxEhProbeError &caught) {
      return -caught.code + opaque(middle.weight);
    }
  } catch (...) {
    return -101 + opaque(outer.weight);
  }
}

/// `throw;` is `__cxa_rethrow`, which resumes the in-flight exception instead
/// of allocating a second one.
extern "C" __attribute__((noinline)) long cxx_eh_probe_bare_rethrow(
    long trigger) {
  try {
    try {
      return raise_when(trigger, 11);
    } catch (const CxxEhProbeError &) {
      throw;
    }
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

/// One live destructor across one throwing call: the smallest frame that
/// carries a cleanup-only landing pad.
extern "C" __attribute__((noinline)) long cxx_eh_probe_cleanup_across_throw(
    long trigger) {
  CleanupCounter held(12);
  return raise_when(trigger, 12) + opaque(held.weight);
}

/// A partially constructed array unwinds element by element, which is a
/// different cleanup action from a single object.
extern "C" __attribute__((noinline)) long cxx_eh_probe_array_cleanup(
    long trigger) {
  CleanupCounter batch[4] = {CleanupCounter(1), CleanupCounter(2),
                             CleanupCounter(4), CleanupCounter(8)};
  return raise_when(trigger, 13) + opaque(batch[3].weight);
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_catch_base_of_derived(
    long trigger) {
  try {
    if (opaque(trigger) == kThrowTrigger) {
      throw CxxEhProbeDerivedError(14);
    }
    return opaque(trigger);
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_catch_virtual_base(
    long trigger) {
  try {
    if (opaque(trigger) == kThrowTrigger) {
      throw CxxEhProbeVirtualDiamond(15);
    }
    return opaque(trigger);
  } catch (const CxxEhProbeVirtualBase &caught) {
    return -caught.tag;
  }
}

/// Three frames between the throw and the catch, each with cleanup work, so
/// the unwind has more than one phase-two stop to make.
extern "C" __attribute__((noinline)) long cxx_eh_probe_deep_propagation(
    long trigger) {
  try {
    return propagate_level_one(trigger);
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_lambda_throw(
    long trigger) {
  auto raiser = [trigger]() -> long { return raise_when(trigger, 18); };
  try {
    return raiser();
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_function_object_throw(
    long trigger) {
  std::function<long(long)> raiser = [](long value) {
    return raise_when(value, 19);
  };
  try {
    return raiser(trigger);
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

/// A `noexcept` body that can throw.  The compiler wraps it in the terminate
/// landing pad, which the ABI spells as an empty exception specification and
/// never as a catch.  The corpus never runs this with the throwing argument,
/// because the only observable outcome would be the death of the process.
extern "C" __attribute__((noinline)) long cxx_eh_probe_noexcept_terminate(
    long trigger) noexcept {
  CleanupCounter held(20);
  return raise_when(trigger, 20) + opaque(held.weight);
}

/// A `return` out of a try block runs the destructor on the normal path as
/// well as the unwind path, so the two share a call and not a landing pad.
extern "C" __attribute__((noinline)) long cxx_eh_probe_return_from_try(
    long trigger) {
  CleanupCounter held(21);
  try {
    if (opaque(trigger) != kThrowTrigger) {
      return opaque(trigger) + opaque(held.weight);
    }
    return raise_when(trigger, 21);
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_loop_try(long trigger) {
  long total = 0;
  for (long index = 0; index < opaque(3); ++index) {
    CleanupCounter step(index + 1);
    try {
      total += raise_when(trigger, 22 + index) + opaque(step.weight);
    } catch (const CxxEhProbeError &caught) {
      total -= caught.code;
    }
  }
  return total;
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_throw_builtin(
    long trigger) {
  try {
    if (opaque(trigger) == kThrowTrigger) {
      throw static_cast<int>(opaque(23));
    }
    return opaque(trigger);
  } catch (int caught) {
    return -static_cast<long>(caught);
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_throw_runtime_error(
    long trigger) {
  try {
    if (opaque(trigger) == kThrowTrigger) {
      throw std::runtime_error("cxx-itanium-eh probe: runtime error");
    }
    return opaque(trigger);
  } catch (const std::exception &) {
    return -24;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_throw_custom(
    long trigger) {
  try {
    if (opaque(trigger) == kThrowTrigger) {
      throw CxxEhProbeError(opaque(25));
    }
    return opaque(trigger);
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

extern "C" __attribute__((noinline)) long cxx_eh_probe_static_local_guard(
    long trigger) {
  try {
    static GuardedInitializer once(trigger);
    return opaque(once.value);
  } catch (const CxxEhProbeError &caught) {
    return -caught.code;
  }
}

#endif  // CXX_EH_PROBE_EXCEPTIONS

namespace {

using ProbeFunction = long (*)(long);

/// Addresses of every probe, so a link that decides to garbage-collect
/// sections cannot drop the ones a given build never reaches.
void anchor_probes() {
  static const ProbeFunction anchors[] = {
      cxx_eh_probe_quiet_sum,
      cxx_eh_probe_cleanup_scope,
      cxx_eh_probe_array_scope,
      cxx_eh_probe_loop_scope,
#if CXX_EH_PROBE_EXCEPTIONS
      cxx_eh_probe_catch_by_value,
      cxx_eh_probe_catch_by_reference,
      cxx_eh_probe_catch_by_pointer,
      cxx_eh_probe_catch_ellipsis,
      cxx_eh_probe_catch_ladder,
      cxx_eh_probe_nested_try,
      cxx_eh_probe_bare_rethrow,
      cxx_eh_probe_cleanup_across_throw,
      cxx_eh_probe_array_cleanup,
      cxx_eh_probe_catch_base_of_derived,
      cxx_eh_probe_catch_virtual_base,
      cxx_eh_probe_deep_propagation,
      cxx_eh_probe_lambda_throw,
      cxx_eh_probe_function_object_throw,
      cxx_eh_probe_noexcept_terminate,
      cxx_eh_probe_return_from_try,
      cxx_eh_probe_loop_try,
      cxx_eh_probe_throw_builtin,
      cxx_eh_probe_throw_runtime_error,
      cxx_eh_probe_throw_custom,
      cxx_eh_probe_static_local_guard,
#endif
  };
  (void)opaque_pointer(anchors);
}

/// The paths that return normally.  Safe under either exception setting, and
/// safe for the `noexcept` probe, which would end the process if it were ever
/// given the throwing argument.
long run_quiet_paths() {
  long total = 0;
  total += cxx_eh_probe_quiet_sum(kQuietValue);
  total += cxx_eh_probe_cleanup_scope(kQuietValue);
  total += cxx_eh_probe_array_scope(kQuietValue);
  total += cxx_eh_probe_loop_scope(kQuietValue);
#if CXX_EH_PROBE_EXCEPTIONS
  total += cxx_eh_probe_catch_by_value(kQuietValue);
  total += cxx_eh_probe_catch_by_reference(kQuietValue);
  total += cxx_eh_probe_catch_by_pointer(kQuietValue);
  total += cxx_eh_probe_catch_ellipsis(kQuietValue);
  total += cxx_eh_probe_catch_ladder(kQuietValue);
  total += cxx_eh_probe_nested_try(kQuietValue);
  total += cxx_eh_probe_bare_rethrow(kQuietValue);
  total += cxx_eh_probe_cleanup_across_throw(kQuietValue);
  total += cxx_eh_probe_array_cleanup(kQuietValue);
  total += cxx_eh_probe_catch_base_of_derived(kQuietValue);
  total += cxx_eh_probe_catch_virtual_base(kQuietValue);
  total += cxx_eh_probe_deep_propagation(kQuietValue);
  total += cxx_eh_probe_lambda_throw(kQuietValue);
  total += cxx_eh_probe_function_object_throw(kQuietValue);
  total += cxx_eh_probe_noexcept_terminate(kQuietValue);
  total += cxx_eh_probe_return_from_try(kQuietValue);
  total += cxx_eh_probe_loop_try(kQuietValue);
  total += cxx_eh_probe_throw_builtin(kQuietValue);
  total += cxx_eh_probe_throw_runtime_error(kQuietValue);
  total += cxx_eh_probe_throw_custom(kQuietValue);
  total += cxx_eh_probe_static_local_guard(kQuietValue);
#endif
  return total;
}

#if CXX_EH_PROBE_EXCEPTIONS

/// The paths that raise.  An exception-free build cannot reach any of them,
/// which is exactly what makes it the negative control.
const char *run_throwing_paths() {
  if (cxx_eh_probe_catch_by_value(kThrowTrigger) != -5) {
    return "catch by value did not observe its int";
  }
  if (cxx_eh_probe_catch_by_reference(kThrowTrigger) != -6) {
    return "catch by const reference did not observe its object";
  }
  if (cxx_eh_probe_catch_by_pointer(kThrowTrigger) != -41) {
    return "catch by pointer did not observe its object";
  }
  if (cxx_eh_probe_catch_ellipsis(kThrowTrigger) != -8) {
    return "catch (...) did not run";
  }
  if (cxx_eh_probe_catch_ladder(kThrowTrigger) != -91) {
    return "the catch ladder chose the wrong clause";
  }

  g_cleanup_log.store(0, std::memory_order_seq_cst);
  if (cxx_eh_probe_nested_try(kThrowTrigger) != 10) {
    return "the inner catch did not run before the outer scope closed";
  }
  if (g_cleanup_log.load(std::memory_order_seq_cst) != 60) {
    return "the nested destructors did not all run";
  }

  if (cxx_eh_probe_bare_rethrow(kThrowTrigger) != -11) {
    return "the bare rethrow did not reach the outer catch";
  }

  g_cleanup_log.store(0, std::memory_order_seq_cst);
  try {
    (void)cxx_eh_probe_cleanup_across_throw(kThrowTrigger);
    return "the cleanup probe did not throw";
  } catch (const CxxEhProbeError &) {
  }
  if (g_cleanup_log.load(std::memory_order_seq_cst) != 12) {
    return "the cleanup destructor did not run while unwinding";
  }

  g_cleanup_log.store(0, std::memory_order_seq_cst);
  try {
    (void)cxx_eh_probe_array_cleanup(kThrowTrigger);
    return "the array cleanup probe did not throw";
  } catch (const CxxEhProbeError &) {
  }
  if (g_cleanup_log.load(std::memory_order_seq_cst) != 15) {
    return "the array elements were not all destroyed while unwinding";
  }

  if (cxx_eh_probe_catch_base_of_derived(kThrowTrigger) != -14) {
    return "the base catch did not accept the derived throw";
  }
  if (cxx_eh_probe_catch_virtual_base(kThrowTrigger) != -15) {
    return "the virtual base catch did not adjust the object";
  }
  if (cxx_eh_probe_deep_propagation(kThrowTrigger) != -16) {
    return "the exception did not cross three frames";
  }
  if (cxx_eh_probe_lambda_throw(kThrowTrigger) != -18) {
    return "the lambda throw was not caught";
  }
  if (cxx_eh_probe_function_object_throw(kThrowTrigger) != -19) {
    return "the std::function throw was not caught";
  }
  if (cxx_eh_probe_return_from_try(kThrowTrigger) != -21) {
    return "the try-with-return probe did not throw";
  }
  if (cxx_eh_probe_loop_try(kThrowTrigger) != -(22 + 23 + 24)) {
    return "the loop body did not catch on every iteration";
  }
  if (cxx_eh_probe_throw_builtin(kThrowTrigger) != -23) {
    return "the builtin throw was not caught";
  }
  if (cxx_eh_probe_throw_runtime_error(kThrowTrigger) != -24) {
    return "the std::runtime_error throw was not caught";
  }
  if (cxx_eh_probe_throw_custom(kThrowTrigger) != -25) {
    return "the custom throw was not caught";
  }
  // The guarded static succeeded on the quiet run, so the guard is already
  // released and the throwing argument must not reinitialize it.
  if (cxx_eh_probe_static_local_guard(kThrowTrigger) != kQuietValue) {
    return "the guarded static was reinitialized after it had succeeded";
  }
  return nullptr;
}

#endif  // CXX_EH_PROBE_EXCEPTIONS

}  // namespace

int main() {
  anchor_probes();
  const long quiet = run_quiet_paths();
  if (quiet < 1) {
    std::fprintf(stderr,
                 "cxx-itanium-eh probe failed: quiet paths summed to %ld\n",
                 quiet);
    return 1;
  }
#if CXX_EH_PROBE_EXCEPTIONS
  if (const char *reason = run_throwing_paths()) {
    std::fprintf(stderr, "cxx-itanium-eh probe failed: %s\n", reason);
    return 1;
  }
#endif
  std::puts("cxx-itanium-eh probe passed");
  return 0;
}
