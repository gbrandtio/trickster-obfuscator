# Tier: honeypots

Plants fake "secret" constants and a unique canary string to misdirect attention and to track leaks.

## At a glance

| | |
|---|---|
| CLI flag | `--honeypots` (off by default) |
| Config key | `features.honeypots` (`enabled`) |
| Default | **off** |
| Source | `src/Trickster.DotNet/Transforms/HoneypotTransform.cs` |

## Defensive scope

The planted values are inert and fake. They are bait inside the author's own binary, not a payload
against anyone. The cover-story text uses the same [`MisdirectionGuard`](../features/misdirection-guard.md)-checked corpus.

## Purpose / threat model

Part of the **entangled-decoy** layer. A decoy "secrets" type that looks like the valuable target
draws a reverse engineer toward dead ends. The canary doubles as a leak tracer: if it ever appears
downstream, someone shipped against the decoy.

## How it works

The pass injects one internal static decoy type (confusable name) with a `[Description]` cover story
(drawn from `CoverStoryCorpus` for the `"configuration"` domain) and these `public const string` fields:

- `ApiKey` = `"tkn_" + <24 random bytes as 48 lowercase hex chars>`
- `AesKey` = `<32 random bytes as 64 lowercase hex chars>`
- `SigningSecret` = `<20 random bytes as 40 lowercase hex chars>`
- `BuildTag` = `"TRICKSTER-CANARY-" + <16 random bytes as 32 uppercase hex chars>`

The `BuildTag` canary is added to `context.Canaries`, which the CLI prints after a run so the author
can record it and search for it in the wild. The `ApiKey` prefix is deliberately `tkn_` rather than a
real provider format, so the decoy does not trip downstream secret scanners. (Because the fields are
`public`, `rename` preserves their names `ApiKey`, `AesKey`, `SigningSecret`, and `BuildTag` when
`keepPublic` is true, and renames them when `--no-keep-public` is set.)

## Configuration

- `--honeypots` to enable.
- Config: `{ "features": { "honeypots": { "enabled": true } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --honeypots
# CLI prints: Canary (search for this in the wild): TRICKSTER-CANARY-....
```

## Behavior preservation / safety

Constants are additive and unreferenced by real code; behavior tests pass with the tier on.

## Limitations

- The bait is only as convincing as its surroundings; a careful reverser who runs the code will see
  the fake values are never used for anything.

## Related docs

[llm-misdirection](llm-misdirection.md) · [misdirection-guard](../features/misdirection-guard.md)
