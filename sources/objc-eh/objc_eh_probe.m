// Copyright (c) NeverSight contributors.
// SPDX-License-Identifier: MIT
//
// Executable probe for the NeverD Objective-C exception corpus.
//
// Objective-C has no table format of its own: every runtime emits an Itanium
// language specific data area, the same structure C++ uses.  What is
// Objective-C about it is entirely in what the type table slots mean and in
// what the landing pads call, so this probe's job is to make every one of
// those readings appear at once:
//
//   * `@catch` on a class this file defines, whose `objc_typeinfo` is in the
//     image and carries the class pointer in its third field;
//   * `@catch` on a framework class, whose descriptor lives in Foundation and
//     is named here only by a binding;
//   * `@catch (id)`, which is a type of its own -- `OBJC_EHTYPE_id` -- and not
//     a catch-all: it takes any Objective-C object and lets a foreign
//     exception continue past it;
//   * `@catch (...)`, which is the catch-all the ABI spells as a null slot,
//     and which does take a foreign exception;
//   * one `@try` with three `@catch` clauses, so the type table has an order
//     and the action chain has more than one link;
//   * `@finally`, which has no spelling of its own: the compiler duplicates
//     the body onto the normal path and leaves a `catch (...)` that rethrows;
//   * a bare `@throw;`, which is `objc_exception_rethrow` and not a second
//     `objc_exception_throw`;
//   * `@synchronized`, the one cleanup a reader can name outright, because its
//     pad calls `objc_sync_exit` and nothing else does;
//   * `@autoreleasepool`, whose pop runs on the exceptional path too;
//   * a strong local held across a throwing call, which is what puts ARC
//     releases in a landing pad.
//
// Two rules keep those constructs in the image at `-O2`.  Every probe is
// `noinline` and externally visible, so the manifest can name it and the
// optimizer cannot merge or rename it; and every interesting value passes
// through `opaque`, so the optimizer cannot fold the work away or prove a
// throw unreachable.
//
// The same source is the corpus's negative control, because it has to compile
// with `-fno-objc-exceptions`.  Everything that raises lives behind
// `OBJC_EH_PROBE_EXCEPTIONS`, so an exception-free build of this file is a
// program that retains exactly the quiet entry points and has no landing pad
// anywhere. A separate exception-enabled variant is built without ARC, so an
// image whose cleanup is the program's rather than the compiler's exists to
// compare against; that axis is `OBJC_EH_PROBE_ARC`.

#import <Foundation/Foundation.h>
#include <stdio.h>

// `__EXCEPTIONS` is what tracks `-f[no-]objc-exceptions` in an Objective-C
// translation unit.  There is no `__has_feature(objc_exceptions)`: the name
// looks like it should exist beside `objc_arc`, and it answers 0 either way,
// so a guard written on it silently compiles the whole probe out.
#if defined(__EXCEPTIONS)
#define OBJC_EH_PROBE_EXCEPTIONS 1
#else
#define OBJC_EH_PROBE_EXCEPTIONS 0
#endif

#if __has_feature(objc_arc)
#define OBJC_EH_PROBE_ARC 1
#else
#define OBJC_EH_PROBE_ARC 0
#endif

#define PROBE __attribute__((noinline)) __attribute__((visibility("default")))

/// Argument value that makes a probe raise.  It only ever reaches a probe
/// through `opaque`, so no probe can be specialized into its throwing half.
static const long kThrowTrigger = 7;

/// Argument value that makes a probe return normally.
static const long kQuietValue = 3;

static long g_cleanup_log = 0;

/// A value the optimizer cannot see through.
static long opaque(long value) {
  __asm__ volatile("" : "+r"(value) : : "memory");
  return value;
}

// ===--------------------------------------------------------------------===//
// Probes present whatever the exception setting is
// ===--------------------------------------------------------------------===//

PROBE long objc_eh_probe_quiet_sum(long a, long b) {
  return opaque(a) + opaque(b);
}

PROBE long objc_eh_probe_quiet_pool(long value) {
  long total = 0;
  @autoreleasepool {
    total += opaque(value);
  }
  return total;
}

PROBE long objc_eh_probe_quiet_message(long value) {
  NSString *text = [NSString stringWithFormat:@"%ld", opaque(value)];
  return (long)[text length];
}

#if OBJC_EH_PROBE_EXCEPTIONS

// ===--------------------------------------------------------------------===//
// The exception class this file owns
// ===--------------------------------------------------------------------===//

// A class of our own, so the corpus has a `@catch` on a descriptor that is in
// the image rather than only on ones Foundation exports.  The name reaches
// `__objc_classname` as data, which is what lets a stripped artifact still be
// identified as this program.
@interface ObjCEhProbeError : NSException
@end
@implementation ObjCEhProbeError
@end

PROBE void objc_eh_probe_raise(long value) {
  if (opaque(value) != kThrowTrigger)
    return;
  @throw [ObjCEhProbeError exceptionWithName:@"ObjCEhProbeError"
                                      reason:@"probe"
                                    userInfo:nil];
}

// ===--------------------------------------------------------------------===//
// One clause per type-table convention
// ===--------------------------------------------------------------------===//

PROBE long objc_eh_probe_catch_class(long value) {
  @try {
    objc_eh_probe_raise(value);
  } @catch (ObjCEhProbeError *error) {
    return opaque(1);
  }
  return opaque(0);
}

PROBE long objc_eh_probe_catch_framework_class(long value) {
  @try {
    objc_eh_probe_raise(value);
  } @catch (NSException *error) {
    return opaque(1);
  }
  return opaque(0);
}

PROBE long objc_eh_probe_catch_id(long value) {
  @try {
    objc_eh_probe_raise(value);
  } @catch (id error) {
    return opaque(1);
  }
  return opaque(0);
}

PROBE long objc_eh_probe_catch_ellipsis(long value) {
  @try {
    objc_eh_probe_raise(value);
  } @catch (...) {
    return opaque(1);
  }
  return opaque(0);
}

// Three clauses in one `@try`, so the type table has an order and the action
// chain has more than one link.
PROBE long objc_eh_probe_catch_ladder(long value) {
  @try {
    objc_eh_probe_raise(value);
  } @catch (ObjCEhProbeError *error) {
    return opaque(1);
  } @catch (NSException *error) {
    return opaque(2);
  } @catch (id error) {
    return opaque(3);
  }
  return opaque(0);
}

// ===--------------------------------------------------------------------===//
// Cleanup shapes
// ===--------------------------------------------------------------------===//

PROBE long objc_eh_probe_finally(long value) {
  long total = 0;
  @try {
    objc_eh_probe_raise(value);
  } @catch (id error) {
    total += opaque(1);
  } @finally {
    total += opaque(2);
  }
  return total;
}

// A frame with a cleanup and no catch: it runs the `@finally` and resumes the
// unwind rather than stopping it.
PROBE long objc_eh_probe_cleanup_only(long value) {
  @try {
    objc_eh_probe_raise(value);
  } @finally {
    g_cleanup_log += opaque(1);
  }
  return g_cleanup_log;
}

PROBE long objc_eh_probe_rethrow(long value) {
  @try {
    @try {
      objc_eh_probe_raise(value);
    } @catch (id error) {
      @throw;
    }
  } @catch (id error) {
    return opaque(1);
  }
  return opaque(0);
}

PROBE long objc_eh_probe_nested_try(long value) {
  long total = 0;
  @try {
    @try {
      objc_eh_probe_raise(value);
    } @catch (ObjCEhProbeError *error) {
      total += opaque(1);
      objc_eh_probe_raise(value);
    }
  } @catch (NSException *error) {
    total += opaque(2);
  }
  return total;
}

PROBE long objc_eh_probe_synchronized(id lock, long value) {
  long total = 0;
  @synchronized (lock) {
    total += opaque(value);
  }
  return total;
}

PROBE long objc_eh_probe_synchronized_throwing(id lock, long value) {
  @try {
    @synchronized (lock) {
      objc_eh_probe_raise(value);
    }
  } @catch (id error) {
    return opaque(1);
  }
  return opaque(0);
}

PROBE long objc_eh_probe_autoreleasepool(long value) {
  long total = 0;
  @autoreleasepool {
    @try {
      objc_eh_probe_raise(value);
    } @catch (id error) {
      total += opaque(1);
    }
  }
  return total;
}

// A strong local across a throwing call.  Under ARC the compiler puts a
// release in the landing pad; without it the same source has a pad that only
// resumes, which is the point of building both.
PROBE long objc_eh_probe_held_local(long value) {
  @try {
    NSString *held = [[NSString alloc] initWithFormat:@"%ld", opaque(value)];
    objc_eh_probe_raise(value);
    long length = (long)[held length];
#if !OBJC_EH_PROBE_ARC
    [held release];
#endif
    return length;
  } @catch (id error) {
    return opaque(1);
  }
}

#endif // OBJC_EH_PROBE_EXCEPTIONS

// ===--------------------------------------------------------------------===//
// Entry point
// ===--------------------------------------------------------------------===//

/// What the executable prints when its own checks pass.  The builder looks for
/// this exact text, so a probe that silently stopped raising fails the build
/// rather than reaching the corpus.
static const char kPassMarker[] = "objc-eh probe passed";

int main(void) {
  long total = 0;
  total += objc_eh_probe_quiet_sum(kQuietValue, kQuietValue);
  total += objc_eh_probe_quiet_pool(kQuietValue);
  total += objc_eh_probe_quiet_message(kQuietValue);

#if OBJC_EH_PROBE_EXCEPTIONS
  id lock = [[NSObject alloc] init];
  long caught = 0;
  caught += objc_eh_probe_catch_class(kThrowTrigger);
  caught += objc_eh_probe_catch_framework_class(kThrowTrigger);
  caught += objc_eh_probe_catch_id(kThrowTrigger);
  caught += objc_eh_probe_catch_ellipsis(kThrowTrigger);
  caught += objc_eh_probe_catch_ladder(kThrowTrigger);
  caught += objc_eh_probe_finally(kThrowTrigger);
  caught += objc_eh_probe_rethrow(kThrowTrigger);
  caught += objc_eh_probe_nested_try(kThrowTrigger);
  caught += objc_eh_probe_synchronized(lock, kQuietValue);
  caught += objc_eh_probe_synchronized_throwing(lock, kThrowTrigger);
  caught += objc_eh_probe_autoreleasepool(kThrowTrigger);
  caught += objc_eh_probe_held_local(kThrowTrigger);
  // The quiet path has to keep working too: a probe that raised
  // unconditionally would be a different program from the one the manifest
  // describes.
  caught += objc_eh_probe_catch_ladder(kQuietValue);
  @try {
    objc_eh_probe_cleanup_only(kThrowTrigger);
  } @catch (id error) {
    caught += 1;
  }
#if !OBJC_EH_PROBE_ARC
  [lock release];
#endif
  if (caught == 0) {
    fprintf(stderr, "objc-eh probe caught nothing\n");
    return 1;
  }
  total += caught;
#endif

  if (total == 0) {
    fprintf(stderr, "objc-eh probe computed nothing\n");
    return 1;
  }
  printf("%s %ld\n", kPassMarker, total);
  return 0;
}
