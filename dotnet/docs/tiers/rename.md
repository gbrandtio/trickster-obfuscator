# Tier: rename

Renames types and members to hostile, hard-to-read identifiers while keeping the public API usable.

## At a glance

| | |
|---|---|
| CLI flag | on by default; `--no-rename` to disable; `--keep-public` / `--no-keep-public` |
| Config key | `features.rename` (`enabled`, `keepPublic`) |
| Default | **on** (`keepPublic: true`) |
| Source | `src/Trickster.DotNet/Transforms/RenameTransform.cs`, `src/Trickster.DotNet/Naming/NameGenerator.cs` |

## Purpose / threat model

Readable identifiers (`ComputeLicenseHash`, `_privateKey`) hand a reverse engineer the program's
intent for free. Renaming removes that signal. This is the **names** tier of the robustness model:
cheap, and it mostly raises cost for a human reader and for de-obfuscation scripts. A capable LLM
largely ignores names, so renaming is not where Trickster defeats LLM analysis — it is the base
layer that the stronger tiers build on.

## How it works

The pass walks every type in the module (`module.GetTypes()`) and renames what it can prove is safe:

- **Types** — renamed unless the type is `<Module>`, an interface, or (when `keepPublic`) public /
  nested-public / nested-family. A renamed top-level type also has its namespace cleared, so its
  full name changes.
- **Methods** — `CanRenameMethod` skips constructors and runtime-special-name methods, property and
  event accessors (`IsGetter`/`IsSetter`/`IsAddOn`/`IsRemoveOn`/`IsFire`), `virtual` / `abstract` /
  `HasOverrides` members, P/Invoke methods, and (when `keepPublic`) public / family members. Renamed
  methods also get their parameters renamed (parameter names have no runtime effect).
- **Fields** — `CanRenameField` skips special-name fields and (when `keepPublic`) public / family
  fields.

New names come from the **shared** generator `context.Names` (a single `NameGenerator` per run, so
names are unique across the whole module — see [architecture](../features/architecture.md)). Names are
built from visually confusable Unicode letters (homoglyphs of `l` / `I` / `o`), length 8–16, so two
distinct identifiers look identical to a human. The old-to-new mapping is recorded in
`context.RenameMap` and can be dumped with `--map`.

## Configuration

- `--no-rename` — turn the tier off.
- `--keep-public` (default) / `--no-keep-public` — preserve or rename the public API surface.
- Config: `{ "features": { "rename": { "enabled": true, "keepPublic": true } } }`.

## Example

```sh
dotnet src/Trickster.Cli/bin/Debug/net9.0/trickster.dll \
  dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only rename --map map.json
```

`internal int ComputeChecksum(int seed)` becomes something like `internal int ӏlІıӏIƖl(int Ilӏ…)`,
while a `public` method keeps its name.

## Behavior preservation / safety

Renaming uses Cecil references, so call sites update automatically. The conservative skip rules
(virtual/override/interface/accessor/P/Invoke) keep dispatch, properties, and interop intact.

## Limitations

- Trickster does **not** detect name-based lookups: `Type.GetMethod("Name")`, serialization by member
  name, DI/convention binding, COM late binding. A renamed member breaks these. Until a skip-list
  exists, keep such members public or run `--no-rename` for that assembly.
- `keepPublic` protects only public and family members; a private member reached by reflection is
  still renamed.

## Related docs

[architecture](../features/architecture.md) · [cli](../features/cli.md) · [feature-flags-and-config](../features/feature-flags-and-config.md)
