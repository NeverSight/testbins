# Manifests

`windows-eh.json` is generated only after all 32 MSVC/clang-cl Windows
exception cells have built and passed validation. It inventories 168 committed
PE artifacts and conforms to `../schema/windows-eh-manifest.schema.json`.

The manifest is the stable interface consumed by NeverD. Do not edit it by
hand; change producer inputs and let the publication workflow regenerate it.
