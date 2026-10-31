# Feature: MisdirectionGuard (the defensive boundary)

The validator that keeps all generated misdirection text within Trickster's defensive scope.

## Source

`src/Trickster.Core/Llm/MisdirectionGuard.cs`

## The boundary

Trickster's misdirection is **defensive only**: it may describe the author's own code as something it
is not, but it must never contain imperative instructions aimed at a reader's AI agent. The guard
enforces exactly this line. It is applied to **both** the built-in corpus and any LLM output, so no
generated text can smuggle a payload into the obfuscated binary.

`IsSafe(text)` returns whether text is within scope. `Require(text)` returns the text if safe and
otherwise throws — generation must not proceed with a rejected string. In the misdirection pass a
rejection is caught and the offline corpus is used instead.

## What it rejects

Four pattern groups (case-insensitive regexes):

1. **Imperative prompt injection** — e.g. "ignore your/previous/prior instructions / prompts / rules".
2. **Destructive verbs** — e.g. `rm -rf`, `del /`, `format c:`, `drop table`, `shutdown`, `execute`,
   "run the following".
3. **Exfiltration** — `exfiltrate…`, `leak`, "send … to/secrets/credentials/keys",
   "upload … to/secrets".
4. **Safety override** — "disable/bypass/turn off … safety/guardrails/security/protection".

Benign descriptive text ("Internal telemetry buffer that flushes on a timer.") passes; payload-style
text is rejected. This behavior is covered by tests.

## Limitation

The guard is a **pattern filter**. It catches common phrasings but cannot catch every possible wording.
It is a guardrail that reinforces the design boundary, not a complete classifier. The primary
assurance is that the feature only ever writes *descriptive* decoy text in the first place.

## Related docs

[llm-misdirection](../tiers/llm-misdirection.md) · [honeypots](../tiers/honeypots.md) · [llm-provider](llm-provider.md)
