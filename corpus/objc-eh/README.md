# Generated Objective-C exception corpus

This tree is synchronized by the `Build and publish Objective-C EH corpus`
workflow after every successful producer change on `main`. Nothing here is
built on a developer's machine, and no binary or manifest is committed by hand.

Do not add, rename, or replace an executable without the matching generated
entry in `manifests/objc-eh.json`. Every path repeats the runtime, target,
optimization level, and symbol state in both its directories and filename, so a
moved artifact cannot be mistaken for one built for its new location.

macOS executables have no file extension. `.gitattributes` therefore marks the
generated artifact directories as binary by path while leaving this notice as
ordinary diffable text.

Workflow artifact transfer does not preserve the executable bit. That is
harmless after publication: NeverD parses these Mach-O images as data. The
producer runs all six arm64 executables on the Apple-silicon build runner before
uploading them; x86_64 slices are explicitly recorded as cross-built and not
run.
