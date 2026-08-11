// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <windows.h>

static const DWORD ProbeExceptionCode = 0xE0421001u;
static volatile LONG ProbeSink = 0;

__declspec(noinline) static LONG probe_filter(EXCEPTION_POINTERS *Pointers) {
  if (Pointers == NULL || Pointers->ExceptionRecord == NULL)
    return EXCEPTION_CONTINUE_SEARCH;
  return Pointers->ExceptionRecord->ExceptionCode == ProbeExceptionCode
             ? EXCEPTION_EXECUTE_HANDLER
             : EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) static int probe_plain_seh(int Value) {
  int Result = 0;
  __try {
    if (Value == 7)
      RaiseException(ProbeExceptionCode, 0, 0, NULL);
    Result = -100;
  } __except (probe_filter(GetExceptionInformation())) {
    Result = 41;
  }
  ProbeSink = Result;
  return Result + 1;
}

__declspec(noinline) static int probe_gs_wrapped_seh(unsigned Index) {
  volatile unsigned char Buffer[64] = {0};
  int Accumulator = 1;
  Index &= 63u;
  Buffer[Index] = 3;

  __try {
    __try {
      RaiseException(ProbeExceptionCode, 0, 0, NULL);
    } __finally {
      Accumulator += AbnormalTermination() ? 10 : 100;
    }
  } __except (probe_filter(GetExceptionInformation())) {
    Accumulator += 20;
  }

  ProbeSink = Accumulator;
  return Accumulator + Buffer[Index];
}

int main(void) {
  const int Plain = probe_plain_seh(7);
  const int Guarded = probe_gs_wrapped_seh(9);
  if (Plain != 42 || Guarded != 34) {
    fprintf(stderr, "SEH probe failed: plain=%d guarded=%d\n", Plain, Guarded);
    return 1;
  }
  puts("SEH probe passed");
  return 0;
}
