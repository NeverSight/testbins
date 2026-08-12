// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT
//
// Shared-library half of the NeverD C++ Itanium exception corpus.
//
// A shared object is not the executable with a different link flag.  The
// exception it raises has to leave the image entirely, which means the type it
// throws has to be matchable from outside, the personality routine has to be
// resolved through the dynamic loader, and the unwinder has to walk out of one
// object file's tables and into another's.  Those are the paths a decompiler
// gets wrong when it only ever sees whole programs.
//
// Every entry point is `extern "C"` and marked with `CXX_EH_SHARED_API`, so the
// three object formats export exactly the same names: `__declspec(dllexport)`
// is what a PE needs, and default ELF and Mach-O visibility is what the other
// two already do.  The library is never compiled with `-fvisibility=hidden`,
// because hiding the exception type's RTTI is what stops a catch in another
// object from matching it.

#include <atomic>

#if defined(_WIN32)
#define CXX_EH_SHARED_API __declspec(dllexport)
#else
#define CXX_EH_SHARED_API __attribute__((visibility("default")))
#endif

/// Every entry point is spelled the same way: exported, C-linkage, and never
/// inlined into its neighbours, so each one keeps a frame of its own for a
/// decoder to find.
#define CXX_EH_SHARED_ENTRY \
  extern "C" CXX_EH_SHARED_API __attribute__((noinline))

namespace {

constexpr long kThrowTrigger = 7;

std::atomic<long> g_cleanup_log{0};

long opaque(long value) {
  __asm__ volatile("" : "+r"(value) : : "memory");
  return value;
}

struct SharedCleanupCounter {
  explicit SharedCleanupCounter(long weight) : weight(opaque(weight)) {}
  ~SharedCleanupCounter() {
    g_cleanup_log.fetch_add(weight, std::memory_order_seq_cst);
  }

  long weight;
};

}  // namespace

/// The library's own exception type.  Its mangled name is the byte string
/// `16CxxEhSharedError`, which is the identity a stripped shared object still
/// carries, so the manifest asserts it.
struct CxxEhSharedError {
  explicit CxxEhSharedError(long value) : code(value) {}
  virtual ~CxxEhSharedError();

  long code;
};

CxxEhSharedError::~CxxEhSharedError() = default;

/// Throws out of the library, so the unwinder has to leave this object's
/// tables and find the caller's.
CXX_EH_SHARED_ENTRY long cxx_eh_shared_raise(long trigger) {
  SharedCleanupCounter held(1);
  if (opaque(trigger) == kThrowTrigger) {
    throw CxxEhSharedError(31);
  }
  return opaque(trigger) + opaque(held.weight);
}

/// Catches its own exception, so the library has a complete try/catch of its
/// own and not only a cleanup edge.
CXX_EH_SHARED_ENTRY long cxx_eh_shared_catch(long trigger) {
  SharedCleanupCounter held(2);
  try {
    return cxx_eh_shared_raise(trigger) + opaque(held.weight);
  } catch (const CxxEhSharedError &caught) {
    return -caught.code;
  }
}

/// Catches, then resumes the same exception with `__cxa_rethrow`, so the
/// exception leaves the library from a landing pad rather than from a throw.
CXX_EH_SHARED_ENTRY long cxx_eh_shared_rethrow(long trigger) {
  SharedCleanupCounter held(4);
  try {
    return cxx_eh_shared_raise(trigger) + opaque(held.weight);
  } catch (...) {
    throw;
  }
}

/// Cleanup only: this frame has destructor work but no catch, so its
/// call-site records point at a landing pad that always resumes.
CXX_EH_SHARED_ENTRY long cxx_eh_shared_cleanup(long trigger) {
  SharedCleanupCounter first(8);
  SharedCleanupCounter second(16);
  return cxx_eh_shared_raise(trigger) + opaque(first.weight) +
         opaque(second.weight);
}

/// Calls back out of the library and catches whatever comes back.  The corpus
/// uses this to send an exception through a C frame in `c_eh_probe`, which is
/// the only way a `__gcc_personality_v0` cleanup table is ever exercised.
CXX_EH_SHARED_ENTRY long cxx_eh_shared_call_and_catch(
    long (*callback)(long), long trigger) {
  SharedCleanupCounter held(32);
  try {
    return callback(trigger) + opaque(held.weight);
  } catch (const CxxEhSharedError &caught) {
    return -caught.code;
  }
}

/// Reads the destructor log, so a caller can prove the cleanups actually ran.
CXX_EH_SHARED_ENTRY long cxx_eh_shared_log(void) {
  return g_cleanup_log.load(std::memory_order_seq_cst);
}
