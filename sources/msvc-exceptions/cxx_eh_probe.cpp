// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT

#include <cstdio>

namespace {

volatile long CleanupCount = 0;

struct Cleanup final {
  explicit Cleanup(long Delta) noexcept : Delta(Delta) {}
  ~Cleanup() noexcept { CleanupCount += Delta; }

  long Delta;
};

struct ProbeError {
  explicit ProbeError(int Value) noexcept : Value(Value) {}
  int Value;
};

struct ProbeBase {
  explicit ProbeBase(int Value) noexcept : Value(Value) {}
  virtual ~ProbeBase() = default;
  int Value;
};

struct ProbeDerived final : ProbeBase {
  explicit ProbeDerived(int Value) noexcept : ProbeBase(Value) {}
};

__declspec(noinline) int probe_nested_catches(int Selector) {
  CleanupCount = 0;
  try {
    Cleanup Outer(1);
    try {
      Cleanup Inner(10);
      if (Selector == 7)
        throw ProbeError(31);
      return -100;
    } catch (const ProbeError &Error) {
      if (Error.Value == 31) {
        try {
          throw ProbeDerived(11);
        } catch (const ProbeBase &Base) {
          return Base.Value + Error.Value;
        }
      }
      return -200;
    }
  } catch (...) {
    return -300;
  }
}

__declspec(noinline) int probe_rethrow() {
  try {
    try {
      throw ProbeError(42);
    } catch (const ProbeError &) {
      throw;
    }
  } catch (const ProbeError &Error) {
    return Error.Value;
  }
}

__declspec(noinline) int probe_gs_buffered_catch(unsigned Index) {
  volatile unsigned char Buffer[64] = {0};
  Index &= 63u;
  Buffer[Index] = 5;
  try {
    Cleanup OnUnwind(100);
    throw ProbeError(37);
  } catch (const ProbeError &Error) {
    return Error.Value + Buffer[Index];
  }
}

} // namespace

int main() {
  const int Nested = probe_nested_catches(7);
  const long Cleanups = CleanupCount;
  const int Rethrown = probe_rethrow();
  const int Guarded = probe_gs_buffered_catch(13);
  if (Nested != 42 || Cleanups != 11 || Rethrown != 42 || Guarded != 42) {
    std::fprintf(stderr,
                 "C++ EH probe failed: nested=%d cleanups=%ld rethrow=%d "
                 "guarded=%d\n",
                 Nested, Cleanups, Rethrown, Guarded);
    return 1;
  }
  std::puts("C++ EH probe passed");
  return 0;
}
