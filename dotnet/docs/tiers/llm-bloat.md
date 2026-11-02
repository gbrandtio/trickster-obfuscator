# Tier: llm-bloat (anti-LLM-analysis volume inflation)

Injects a configurable, large number of inert decoy types so the author's own binary is
token-expensive to analyze when an attacker decompiles it and feeds the output to an LLM.

## At a glance

| | |
|---|---|
| CLI flag | off by default; `--llm-bloat` to enable, `--no-llm-bloat` to disable |
| Config key | `features.llmBloat` (`enabled`, `intensity`, `maxTypes`) |
| Default | **off** (dual-use) |
| Source | `src/Trickster.DotNet/Transforms/LlmBloatTransform.cs` |

## Defensive scope

This tier is **passive volume inflation of the author's own binary only**. It mirrors the boundary
documented for [llm-misdirection](llm-misdirection.md): it does **not** generate prompt-injection
payloads or any content aimed at a third party's AI agent, and it does not attack any LLM service.
That boundary is made structural rather than merely intended: the injected decoy methods are fully
inert and emit **no string literals, no `[Description]` metadata, and no readable narrative at all**
(each method is a type-correct no-op). With no emitted text there is no payload surface, and nothing
in this tier sends data anywhere.

## Purpose / threat model

A common reverse-engineering workflow is to decompile a protected assembly and paste the result into
an LLM for summarization or deobfuscation. LLMs have bounded context windows, so a module that
decompiles into a large, low-signal body of source degrades that automated analysis: the analyst's
tool overflows its window or spends its token budget on inert filler. This is the LLM-era analogue
of [decompiler-poison](decompiler-poison.md) (which degrades *decompilers*); this tier degrades
*LLM-assisted analysis* by raw volume.

## How it works

`intensity` sets the base number of inert decoy types injected: `low` = 25, `medium` = 75,
`high` = 200 (any other value → `medium`). The resolved count is then clamped by `maxTypes`
(default `500`), so output size cannot balloon unboundedly: `count = min(intensity-value, maxTypes)`,
where `intensity-value` is the number the intensity level maps to.

For each decoy type the pass creates an internal sealed class in namespace `Trickster.Bloat` with a
name from the shared `NameGenerator` (`context.Names`, so no collisions with real or other generated
identifiers), a default constructor, and a small fixed number of `private static` methods whose
bodies are type-correct no-ops (`ldc.i4.0; ret`). The types are additive and never referenced by
real code.

The tier runs late in the pipeline (`Order 85`, after `rename`/`integrity`, before `antidebug`), so
the earlier structural passes do not churn over the large volume of decoys.

## Configuration

- `--llm-bloat` / `--no-llm-bloat`: turn the tier on/off.
- `features.llmBloat.intensity`: `"low"` | `"medium"` | `"high"`.
- `features.llmBloat.maxTypes`: hard ceiling on injected types (default `500`).
- `--only llmbloat` / `--off llmbloat`: include/exclude the tier via the generic overlays.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --llm-bloat
# amount + cap via config:
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --config bloat.json --only llmbloat
```

## Behavior preservation / safety

Decoy types are additive and inert; they do not touch existing code. The behavior tests run with this
tier enabled and confirm identical program output (`LlmBloat_PreservesBehavior`,
`LlmBloat_InjectsManyInertTypes`, `LlmBloat_OffByDefault` in `TierBehaviorTests.cs`).

## Limitations

- Volume inflation increases the output assembly's on-disk size; tune with `intensity` / `maxTypes`.
- A sophisticated analyst can filter out the `Trickster.Bloat` namespace; its value is additive on top
  of the strip-resistant tiers, and the decoy type names are themselves renamed-style confusables.

## Related docs

[decompiler-poison](decompiler-poison.md) · [llm-misdirection](llm-misdirection.md) · [feature-flags-and-config](../features/feature-flags-and-config.md)
