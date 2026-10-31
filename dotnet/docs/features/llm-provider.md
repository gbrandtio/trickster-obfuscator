# Feature: LLM provider

The optional, provider-agnostic seam used by the misdirection tier to generate cover stories, with a
full offline fallback.

## Source

`src/Trickster.Core/Llm/ILlmProvider.cs`, `src/Trickster.Core/Llm/OfflineProvider.cs`,
`src/Trickster.Llm.Claude/ClaudeLlmProvider.cs`

## The seam

`ILlmProvider` exposes:

- `bool IsEnabled`
- `Task<IReadOnlyList<string>> SuggestDecoyNamesAsync(string fakeDomainHint, int count, ...)`
- `Task<string> GenerateCoverStoryAsync(string fakeDomainHint, ...)`

The [misdirection tier](../tiers/llm-misdirection.md) calls `GenerateCoverStoryAsync` (one request per
decoy type). Decoy **names** come from the shared `NameGenerator`, not from the provider, so
`SuggestDecoyNamesAsync` is part of the interface but not on the v1 misdirection path.

## Offline provider (default)

`OfflineProvider` needs no network and no key. `IsEnabled` is `false`; it assembles names from a
`Prefixes × Roles` template and cover stories from a fixed template, driven by the entropy source (so
output still varies per build when entropy is non-deterministic). Its cover story is passed through
[`MisdirectionGuard`](misdirection-guard.md).

## Claude provider

Selected with `--llm claude` (or `llm.provider = "claude"`). `ClaudeLlmProvider.FromEnvironment()`
reads `ANTHROPIC_API_KEY`; if the key is absent the CLI warns and falls back to the offline provider.

- Model: **`claude-opus-5-5`** (via the official Anthropic C# SDK).
- One request per decoy type (so 2, 5, or 12 requests depending on `intensity`).
- The prompt contains only a domain name from a built-in list plus fixed instruction text. **Your
  assembly and its code are never sent.**
- Every response passes through `MisdirectionGuard.Require`. If a call fails or its output is
  rejected, the misdirection pass logs a warning and uses the offline corpus for that decoy, so a
  provider outage never aborts obfuscation.

## Configuration

- `--llm claude` + `ANTHROPIC_API_KEY`, or `--llm off` (default).
- Config: `{ "llm": { "provider": "claude" } }`.

## Related docs

[llm-misdirection](../tiers/llm-misdirection.md) · [misdirection-guard](misdirection-guard.md) · [cli](cli.md)
