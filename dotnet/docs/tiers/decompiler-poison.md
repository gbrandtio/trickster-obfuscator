# Tier: poison (decompiler poisoning)

Adds inert decoy members whose names are valid CLR metadata but not valid C#, so common decompilers
emit awkward or misleading output.

## At a glance

| | |
|---|---|
| CLI flag | `--poison-decompilers` (off by default) |
| Config key | `features.decompilerPoison` (`enabled`) |
| Default | **off** |
| Source | `src/Trickster.DotNet/Transforms/DecompilerPoisonTransform.cs` |

## Purpose / threat model

Most reverse engineers start from a decompiler. If the analyst's own tools render broken or confusing
C#, the misdirection comes from the toolchain, not just from comments. This complements the other
tiers by degrading the quality of the reconstructed source an LLM or human would read.

## How it works

The pass injects one type (name `"<>c__" + <confusable>`) containing several `static void` methods
with names chosen to resemble compiler-generated artifacts but which are not valid C# identifiers,
for example `"<>c__DisplayTrap"`, `"<Poison>b__0"`, `"<>9__Decoy"`, `"get_<trap>k__"`,
`"<Finally>d__7"`. Each method body is a single `ret`. The members are unreferenced and do nothing;
the CLR loads them fine, but decompilers must escape or mishandle the names.

## Configuration

- `--poison-decompilers` to enable.
- Config: `{ "features": { "decompilerPoison": { "enabled": true } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --poison-decompilers
```

## Behavior preservation / safety

Members are additive, inert, and unreferenced. This tier carries a higher runtime-validity risk than
the others (hostile metadata), so it is **opt-in** and must round-trip load; the behavior tests run
with it enabled and confirm the assembly still loads and runs.

## Limitations

- Effectiveness depends on the specific decompiler; a hardened or updated tool may handle the names
  gracefully. It does not impede a reverser working at the IL level.

## Related docs

[rename](rename.md) · [architecture](../features/architecture.md)
