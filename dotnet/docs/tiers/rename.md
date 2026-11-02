# Tier: rename

Renames types and members to hostile, hard-to-read identifiers while keeping the public API usable.

## At a glance

| | |
|---|---|
| CLI flag | on by default; `--no-rename` to disable; `--keep-public` / `--no-keep-public`; `--rename-exclude <a,b,...>` |
| Config key | `features.rename` (`enabled`, `keepPublic`, `exclude`) |
| Default | **on** (`keepPublic: true`, `exclude: []`) |
| Source | `src/Trickster.DotNet/Transforms/RenameTransform.cs`, `src/Trickster.DotNet/Naming/NameGenerator.cs` |

## Purpose / threat model

Readable identifiers (`ComputeLicenseHash`, `_privateKey`) hand a reverse engineer the program's
intent for free. Renaming removes that signal. This is the **names** tier of the robustness model:
cheap, and it mostly raises cost for a human reader and for de-obfuscation scripts. A capable LLM
largely ignores names, so renaming is not where Trickster defeats LLM analysis; it is the base
layer that the stronger tiers build on.

## How it works

The pass walks every type in the module (`module.GetTypes()`) and renames what it can prove is safe:

- **Types**: renamed unless the type is `<Module>`, an interface, a decoy type in
  `context.PreservedDecoyTypes`, matched by `features.rename.exclude` or `[Obfuscation(Exclude = true)]`,
  or (when `keepPublic`) public / nested-public / nested-family / nested-family-or-assembly (`protected internal`).
  A renamed top-level type also has its namespace cleared, so its full name changes. (When a type carries
  `[Obfuscation(Exclude = true, ApplyToMembers = true)]`, its members are also skipped.)
- **Methods**: `CanRenameMethod` skips constructors and runtime-special-name methods, property and
  event accessors (`IsGetter`/`IsSetter`/`IsAddOn`/`IsRemoveOn`/`IsFire`), `virtual` / `abstract` /
  `HasOverrides` members, P/Invoke methods, methods matched by `exclude` or `[Obfuscation(Exclude = true)]`,
  and (when `keepPublic`) public / family / family-or-assembly (`protected internal`) members. Renamed
  methods also get their parameters renamed (parameter names have no runtime effect).
- **Fields**: `CanRenameField` skips special-name (`IsSpecialName` / `IsRuntimeSpecialName`) fields,
  fields matched by `exclude` or `[Obfuscation(Exclude = true)]`, and (when `keepPublic`) public /
  family / family-or-assembly (`protected internal`) fields.

New names come from the **shared** generator `context.Names` (a single `NameGenerator` per run, so
names are unique across the whole module; see [architecture](../features/architecture.md)). Names are
built from visually confusable Unicode letters (six vertical-stroke homoglyphs of `l` / `I`: `l`, `I`, `ı`, `ӏ`, `І`, `Ɩ`), length 8-16, so two
distinct identifiers look identical to a human. The old-to-new mapping for renamed types (`T:`), methods (`M:`), and fields (`F:`) is recorded in
`context.RenameMap` (and counted in `RenamedSymbols`) and can be dumped with `--map`.

## Configuration

- `--no-rename`: turn the tier off.
- `--keep-public` (default) / `--no-keep-public`: preserve or rename the public API surface.
- `--rename-exclude <a,b,...>`: comma-separated symbol names or `*` wildcard patterns (matching simple
  `Name`, `DeclaringType.Name`, or `FullName`) to exempt from renaming.
- Config: `{ "features": { "rename": { "enabled": true, "keepPublic": true, "exclude": ["MySecretHelper", "SampleNamespace.*"] } } }`.

## Example

```sh
dotnet src/Trickster.Cli/bin/Debug/net9.0/trickster.dll \
  dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only rename --rename-exclude Classify --map map.json
```

`internal int ComputeChecksum(int seed)` becomes something like `internal int ӏlІıӏIƖl(int Ilӏ…)`,
while a `public` method or an excluded symbol keeps its name.

## Behavior preservation / safety

Renaming uses Cecil references, so call sites update automatically. The conservative skip rules
(virtual/override/interface/accessor/P/Invoke) plus `exclude` and `[Obfuscation]` support keep dispatch,
properties, reflection targets, and interop intact.

## Limitations

- Trickster does **not** automatically scan string arguments to `Type.GetMethod("Name")`, reflection
  calls, or serializer conventions. Mark reflection-targeted private or `internal` members with
  `[Obfuscation(Exclude = true)]` or list them in `--rename-exclude` / `features.rename.exclude`.

## Related docs

[architecture](../features/architecture.md) · [cli](../features/cli.md) · [feature-flags-and-config](../features/feature-flags-and-config.md)
