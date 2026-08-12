# go-eh integration notes

The `go-eh` product line is complete except for four shared files that another
product line is being added to at the same time. The additions those files need
are written out below verbatim so they can be merged by hand without a
conflict. Nothing in this document is applied automatically.

Everything else — `schema/go-eh-manifest.schema.json`, `scripts/go_matrix.py`,
`scripts/build_go_corpus.py`, `scripts/merge_go_corpus.py`,
`scripts/verify_go_corpus.py`, `scripts/tests/test_go_*.py`,
`sources/go-eh/**`, `corpus/go-eh/README.md`, and
`.github/workflows/build-go-eh.yml` — is in place.

---

## 1. Addition for the root `README.md`

Insert after the `## Windows exception corpus` section and before
`## Test inputs`, and extend the `## Repository layout` block as shown at the
end.

````markdown
## Go runtime-metadata corpus

Go does not use any platform exception model. A Go image carries no `.pdata`,
`.eh_frame`, or `__unwind_info` for its own code; the linker emits a `pclntab`
describing every function and the runtime walks it to run deferred calls and to
unwind a panic. The Go producer therefore has one dominant axis — the toolchain
release, because the `pclntab` header changed shape at Go 1.16, Go 1.18, and
Go 1.20 — and a second axis for how hard the table is to find.

| Go release | pclntab magic | Header layout | Cells | Artifacts |
|---|---|---|---|---:|
| 1.15.15 | `0xfffffffb` | `go1.2` | 1 | 5 |
| 1.16.15 | `0xfffffffa` | `go1.16` | 1 | 2 |
| 1.18.10 | `0xfffffff0` | `go1.18` | 1 | 2 |
| 1.20.14 | `0xfffffff1` | `go1.20` | 1 | 1 |
| 1.26.5 | `0xfffffff1` | `go1.20` | 1 | 13 |

The complete matrix contains 5 cells and 23 artifacts. One cell is one pinned
toolchain and one CI job; the artifacts inside it are the GOOS/GOARCH,
buildmode, cgo, link-mode, and optimization variants that release supports.

Targets are `linux/amd64`, `linux/arm64`, `windows/amd64`, `darwin/amd64`, and
`darwin/arm64`. All of them are cross-compiled from one ubuntu x64 runner:
`CGO_ENABLED=0` makes the Go toolchain a complete cross-compiler, and building
every image on one host in one job removes the last way two artifacts could
differ for a reason the manifest does not record. `linux/amd64` executables are
run on the runner before publication; nothing else is claimed to have run.

Every build uses `-trimpath`, without exception, so the CI checkout path does
not reach the file table the corpus publishes.

### What the axes are for

- **Link mode.** `-ldflags=-s -w` removes the symbol table, which is the normal
  shape of a shipped Go program and the case that forces a decoder to find the
  `pclntab` structurally instead of through `runtime.pclntab` or `go:func.*`.
  Most artifacts are stripped; the unstripped ones exist so the symbol-driven
  path is covered too.
- **Buildmode.** Through Go 1.25 a position-independent ELF moved the table
  from `.gopclntab` to `.data.rel.ro.gopclntab`; CL 718065 moved it back for
  Go 1.26, on the grounds that the table holds no relocations and so does not
  belong in the relro segment. A `c-shared` object has no executable entry
  point at all. Both change where `moduledata` ends up. `pie` on darwin and
  Windows is omitted: darwin is already position independent by default, and
  the Windows PIE image reaches its table exactly as the exe image does.
- **cgo.** `CGO_ENABLED=1` links C objects, which bring real DWARF `.eh_frame`
  into an image that otherwise has no platform unwind table for its own code.
  Only the native target has a C toolchain, so cgo cells are `linux/amd64`.
- **Optimization.** `-gcflags=all=-N -l` clears `ssagen.hasOpenDefers` for every
  function, so the same source produces heap and stack `_defer` records instead
  of an open-coded defer bitmask.

### Validation levels

- `runtime-graph`: module state, `_func` records, and funcdata-derived defer
  state are all expected.
- `table-only`: the Go 1.2 header predates `PCDATA_UnsafePoint`, so the
  async-preemption partition cannot be recovered and the parse is expected to
  report partial. Everything the table itself holds is still expected.

### Producer checks

```bash
python3 -m unittest discover -s scripts/tests -p "test_go_*.py" -v
python3 -m py_compile \
  scripts/go_matrix.py \
  scripts/build_go_corpus.py \
  scripts/merge_go_corpus.py \
  scripts/verify_go_corpus.py
python3 -m json.tool schema/go-eh-manifest.schema.json >/dev/null
python3 scripts/go_matrix.py --plan
```

One cell can be built on any Linux host that has the pinned toolchain:

```bash
python3 scripts/build_go_corpus.py \
  --go-version 1.26.5 \
  --output-root ./staging
```

Validate the assembled corpus with:

```bash
python3 scripts/verify_go_corpus.py \
  manifests/go-eh.json \
  --root . \
  --require-complete-matrix \
  --require-schema-validation
```

The verifier re-hashes every artifact and then re-derives every structural
claim from the bytes: it parses the ELF, PE, or Mach-O section table in pure
Python, reads the eight-byte `pcHeader` and its function count, reads the
symbol table to see whether any Go name survived, and sweeps the whole image to
confirm no second plausible table would make a structural scan ambiguous.
`jsonschema` is used for the manifest schema when it is installed and skipped
otherwise; `--require-schema-validation` turns that skip into a failure.
````

Extend the `## Repository layout` block with these two lines:

```text
corpus/go-eh/            Committed generated Go images
sources/go-eh/           Go runtime-metadata probe module
```

---

## 2. Addition for `manifests/README.md`

Append:

```markdown
`go-eh.json` is generated only after all 5 pinned Go toolchain cells have built
and passed validation. It inventories 23 committed Go images and conforms to
`../schema/go-eh-manifest.schema.json`. Its structural evidence records where
each image's `pclntab` is, the header's magic, pc quantum, pointer size, and
function count, and whether the link left any Go symbol behind.

The manifest is the stable interface consumed by NeverD. Do not edit it by
hand; change producer inputs and let the publication workflow regenerate it.
```

---

## 3. Addition for `.gitattributes`

Go executables for `linux` and `darwin` have no extension, so no existing
pattern in this file covers them. `* text=auto eol=lf` will not corrupt them in
practice, because Git's content inspection sees a NUL byte in the first few
bytes of an ELF or Mach-O image and classifies it as binary — but relying on a
heuristic for a corpus whose whole purpose is byte-exact reproduction is the
wrong trade. Add:

```gitattributes
# Committed Go images: most have no extension, because that is what a Go
# executable for linux and darwin is called.
corpus/go-eh/** -text
sources/go-eh/** text eol=lf

*.so binary
*.dylib binary
```

---

## 4. Addition for `.gitignore`

```gitignore
# Go
sources/go-eh/**/go.sum
staging-go/
*.test
```

`sources/go-eh` has no dependencies, so a `go.sum` appearing there means
something was added that the pinned Go 1.15 toolchain will not be able to
fetch with `GOPROXY=off`. `scripts/tests/test_go_sources.py` fails if one is
committed; the ignore entry keeps a local experiment from being staged by
accident.

---

## 5. Notes for whoever merges this

### The Windows workflow's path filters also match go-eh changes

`.github/workflows/build-windows-eh.yml` triggers on `schema/**`, `scripts/**`,
and `sources/**`. Every file added here is under one of those, so a change to
the Go producer will rebuild all 32 Windows cells for nothing. The Go workflow
names its own files individually to avoid the reverse problem. Narrowing the
Windows filters the same way is a one-file change that was deliberately not
made here, because that file belongs to another product line.

### Projected committed size

Twenty-three artifacts, projected at **≈29 MB** in the working tree.

The projection comes from a real end-to-end run of this producer against Go
1.23.6, which produced eight artifacts totalling 10.78 MB:

| Shape | Measured |
|---|---|
| stripped exe, `linux/amd64` | 1.13 MB |
| stripped exe, `-N -l`, `linux/amd64` | 1.13 MB |
| unstripped exe, `linux/amd64` | 1.75 MB |
| stripped pie, `linux/amd64` | 1.25 MB |
| stripped exe, `windows/amd64` | 1.22 MB |
| stripped exe, `darwin/arm64` | 1.24 MB |
| unstripped exe, `darwin/arm64` | 1.84 MB |
| stripped c-shared, cgo, `darwin/arm64` | 1.22 MB |

Seventeen of the twenty-three artifacts are stripped for exactly this reason.
Releases older than 1.23 come out smaller and 1.26 slightly larger, so the
projection uses the measured figures directly. This is roughly ten times the
current repository, which is the unavoidable cost of a Go corpus: the runtime
is in every binary. If it needs to shrink, the cheapest cuts in order are the
`darwin/amd64` cells, the `1.20.14` cell, and the unstripped `windows/amd64`
cell, worth about 4.5 MB together.

Git compresses these to roughly half, so the pack cost is nearer 15 MB. No
git-lfs is introduced.

### What the corpus deliberately does not cover

- **The genuinely old Go 1.2 to Go 1.11 record shape.** `GoRuntimeEH.cpp` votes
  on `PreGo112Record`, a `_func` layout in which `nfuncdata` is a whole word and
  `deferreturn` does not exist. The Go 1.2 magic spans Go 1.2 through Go 1.15,
  and Go 1.15.15 — the newest release that writes that magic and the oldest
  `actions/setup-go` can install on a current runner — uses the *post*-1.12
  shape. A real pre-1.12 image would need a toolchain from 2018 or earlier
  running on ubuntu 24.04, which is not something this producer can honestly
  claim to do. That branch stays covered by the synthetic tables in
  `unittests/lift/GoRuntimeEHTests.cpp`.
- **`PCDATA_StackMapIndex` at index 0.** Go 1.13 moved it to index 1 and the
  magic does not distinguish the two, so the decoder probes for it. Go 1.15.15
  has it at index 1, so the corpus exercises the probe but only ever with the
  answer the probe should reach. The index-0 case is synthetic-only, for the
  same reason as above.
- **32-bit targets.** The decoder accepts `Arch::X86` and `Arch::ARM`, and a
  `pcHeader` with `ptrSize == 4` is a shape it handles. `linux/386` and
  `linux/arm` would cover it at about 1 MB each. They are omitted for size, not
  because they would not be useful; adding them is two lines in
  `_BASE_TARGETS`.
- **Go 1.17, 1.19, and 1.21 through 1.25.** None of them introduced a new
  `pcHeader` magic or `_func` shape. Go 1.17's register ABI and Go 1.25's move
  from `runtime.goPanicIndex` to `runtime.panicBounds` both change the emitted
  code, but the decoder classifies both under the same
  `runtime.goPanic*`/`runtime.panic*` prefixes, and the 1.20.14 and 1.26.5 cells
  already hold one image of each form.
- **`windows/arm64` and `windows/386`.** No new decoder branch: PE discovery is
  already covered by `windows/amd64`, and the pc quantum by `linux/arm64`.
- **`-buildmode=plugin` and `-buildmode=c-archive`.** A plugin would give the
  decoder a second `moduledata` in one process, which is interesting, but it is
  a runtime property rather than an image property and the decoder reads one
  image at a time.

### Which decoder branch each cell reaches

| Cell | `GoRuntimeEH.cpp` path |
|---|---|
| `go1.15.15` | `Go12Magic`, `decodeGo12PcHeader`, `usesPreGo112Record` vote, `FuncDataOpenCodedDeferInfoPreGo116` (index 5), `HasUnsafePointTable == false`, `resolveStackMapPCDataIndex` probe |
| `go1.16.15` | `Go116Magic`, `EntryIsOffset == false`, `FuncDataIsPointer == true`, header size `PtrSize + 36` |
| `go1.18.10` | `Go118Magic`, `entryoff` offsets, 32-bit funcdata offsets from `moduledata.gofunc`, `FuncIDOffset == 36` |
| `go1.20.14`, `go1.26.5` | `Go120Magic`, `FuncIDOffset == 40`, `startLine` present |
| `windows/amd64` (any) | `findPcHeader` segment scan, because the PE linker folds the table into `.rdata` |
| `darwin/*` (any) | `section_names::macho::GoPclnTab`, table in `__DATA_CONST` |
| `linux/*` `pie` (Go &le; 1.25) | the `.data.rel.ro.gopclntab` name in `findPcHeader`'s section list |
| `linux/*` `pie` (Go &ge; 1.26) | the plain `.gopclntab` name, which is why that list has to keep both |
| `linux/arm64` | `MinLC == 4`, so every `forEachPCValue` advance is scaled |
| stripped cells | `findModuleData` plus the `textsectmap` anchor in `decodeModuleData`, with no `go:func.*` symbol to short-circuit it |
| unstripped cells | the `Sym.Name == "go:func.*" || "go.func.*"` shortcut, and `kAutoFuncPrefix` symbol replacement |
| `noopt` cell | `EH.Defers` populated from `deferproc`/`deferprocStack` sites with `UsesOpenCodedDefers == false` throughout |
| `cgo1` cells | a Go image that also has `.eh_frame`, so the Go path must not be shadowed by the DWARF one |

### First publication

An empty product line cannot be published by a workflow that has not run. The
order is the same as the Windows corpus:

1. Review the sources, scripts, schema, workflow, and this document.
2. Merge the four additions above by hand.
3. Push the producer to `main`.
4. The workflow builds and pushes the first generated `corpus/go-eh` commit.
5. NeverD records that reviewed `testbins` commit as its submodule gitlink.
