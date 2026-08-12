# C++ Itanium exception probes

Three self-contained sources with no dependency beyond the C and C++ standard
libraries, compiled by the drivers directly rather than through a build system,
so that every flag in the manifest is a flag the producer actually passed.

| Source | Programs | Kind | Role |
|---|---|---|---|
| `cxx_eh_probe.cpp` | `cxx_eh_probe`, `cxx_eh_probe_noexc` | `exe` | Runnable probe, and its own exception-free negative control |
| `cxx_eh_shared.cpp` | `libcxx_eh_shared` | `shared` | The same machinery behind a shared-object boundary |
| `c_eh_probe.c` | `c_eh_probe` | `exe` | C compiled with `-fexceptions`, so a C++ exception crosses a C frame |

## What each construct is for

| Construct | What NeverD recovers from it |
|---|---|
| `catch` by value, by const reference, by pointer | Three type-table match forms, and three ways `__cxa_begin_catch` hands the object over |
| One try with four catch clauses | Type-table order and an action chain with more than one link |
| `catch (...)` | The catch-all entry, spelled as type index zero |
| `throw;` | `__cxa_rethrow`, not a second `__cxa_throw` |
| A local with a non-trivial destructor across a throw | A cleanup-only call-site record |
| An array of such locals | Element-by-element cleanup, a different action from a single object |
| Nested try, and a throw crossing three frames | More than one landing pad per frame, and more than one phase-two stop |
| A base catch for a derived throw | A constant pointer adjustment between the two |
| The same through virtual inheritance | The adjustment as a lookup rather than a constant |
| A lambda and a `std::function` | A throw from a call the frame does not name |
| A `noexcept` body that can throw | The terminate landing pad: an empty exception specification, never a catch |
| `return` from inside a try | A destructor shared by the normal path and the unwind path |
| A try inside a loop | The same landing pad reached from several call sites |
| A function-scope static whose initializer throws | `__cxa_guard_acquire` and the `__cxa_guard_abort` cleanup edge |
| `__attribute__((cleanup))` in C with `-fexceptions` | A `__gcc_personality_v0` table with cleanup actions and no type table at all |

## Rules the sources have to keep

Every entry point is `extern "C"`, `__attribute__((noinline))`, and called from
`main`, so the manifest can name it and `-O2` cannot rename, merge, or drop it.
Every interesting value passes through `opaque`, an empty `asm volatile` with a
memory clobber, so the optimizer cannot fold the work away or prove a throw
unreachable. `cxx_eh_probe` additionally takes the address of every probe in
`anchor_probes`, because a link that garbage-collects sections would otherwise
drop the ones a given build never reaches.

`cxx_eh_probe.cpp` has to compile with `-fno-exceptions`, because that build is
the corpus's negative control. Everything that raises -- including the exception
types themselves, so the control has no RTTI to give it away -- lives behind
`CXX_EH_PROBE_EXCEPTIONS`. The same source is therefore an executed positive
control in a throwing build and a landing-pad-free negative control in an
exception-free one.

The `noexcept` probe is never called with the throwing argument. Its only
observable outcome would be the death of the process, so the corpus builds the
terminate landing pad and does not walk into it.

`scripts/tests/test_cxx_itanium_sources.py` fails if a probe is added, renamed,
or moved across the exception guard without updating the symbol inventory the
manifest and verifier share, and if either exception type is renamed without its
mangled name following it into the manifest's string evidence.
