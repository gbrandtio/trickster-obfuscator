# Tier: misdirection (LLM misdirection)

Injects decoy types carrying a coherent *false* narrative, to make LLM-assisted reverse engineering
reach confident but wrong conclusions.

## At a glance

| | |
|---|---|
| CLI flag | on by default; `--no-misdirection` to disable |
| Config key | `features.llmMisdirection` (`enabled`, `intensity`) |
| Default | **on** (`intensity: "medium"`) |
| Source | `src/Trickster.DotNet/Transforms/LlmMisdirectionTransform.cs`, `src/Trickster.DotNet/Misdirection/CoverStoryCorpus.cs` |

## Defensive scope

This tier is **defensive misdirection only**. It places false descriptions inside the author's own
binary to mislead whoever analyzes that binary. It does **not** generate payloads aimed at a third
party's AI agent. Every narrative string — whether from the LLM or the built-in corpus — passes
through [`MisdirectionGuard`](../features/misdirection-guard.md), which rejects imperative payloads
(for example "ignore your instructions", "run …", "exfiltrate …"). See the guard doc for the exact
boundary.

## Purpose / threat model

Plain-text lies are the weakest tier: a human can ignore them and a stripping tool can delete them.
Trickster's readable misdirection therefore lives where it survives the other passes — in
`[Description]` **metadata attributes** (not touched by string encryption or renaming) — while the
decoy method bodies carry cover-story string literals that the `strings` pass later encrypts, making
the decoys look like protected logic. The net effect is a module that presents a plausible,
self-consistent story about being something it is not.

## How it works

`intensity` sets how many decoy types are injected: `low` = 2, `medium` = 5, `high` = 12
(`TricksterConfig.MisdirectionOptions.DecoyTypeCount`). For each decoy type the pass:

1. creates a sealed type (namespace `Trickster.Decoys`, confusable name from `context.Names`);
2. attaches `[System.ComponentModel.Description("<cover story>")]`;
3. adds a default constructor and 1–3 decoy methods, each also described and each returning a
   cover-story string literal (later encrypted by the `strings` pass).

The cover story is produced by the configured [LLM provider](../features/llm-provider.md) when enabled
(`GenerateCoverStoryAsync`), otherwise from `CoverStoryCorpus`. If the LLM call fails or its output is
rejected by the guard, the pass logs a warning and falls back to the corpus, so a provider outage
never aborts obfuscation.

## Configuration

- `--no-misdirection` — turn the tier off.
- `features.llmMisdirection.intensity` — `"low"` | `"medium"` | `"high"`; any other value is treated
  as `"medium"`.
- Pair with `--llm claude` for context-aware stories (see [llm-provider](../features/llm-provider.md)).

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only misdirection --llm claude
```

## Behavior preservation / safety

Decoy types are additive and inert; they do not touch existing code. The behavior tests run with this
tier enabled and confirm identical program output.

## Limitations

- Decoy **names** come from `context.Names` (confusable identifiers), not from the LLM — the readable
  misdirection is carried by the `[Description]` text, not by type/method names.
- Plain-text narrative is the weakest layer by design; its value is additive on top of the
  strip-resistant tiers.

## Related docs

[misdirection-guard](../features/misdirection-guard.md) · [llm-provider](../features/llm-provider.md) · [honeypots](honeypots.md)
