# Feature: feature flags and config

Every tier lives behind an independent flag. Nothing is hardwired into the pipeline — a disabled
transform is never constructed or run.

## Source

`src/Trickster.Core/TricksterConfig.cs`

## Resolution precedence

`CLI flags > config file (--config) > built-in defaults`. Load a file with `--config`; property names
are case-insensitive and the parser allows comments and trailing commas.

## Schema

```json
{
  "seedFile": "keys/build.seed",
  "llm": { "provider": "off" },
  "features": {
    "rename":           { "enabled": true,  "keepPublic": true },
    "stringEncryption": { "enabled": true },
    "controlFlow":      { "enabled": true,  "opaquePredicates": true },
    "llmMisdirection":  { "enabled": true,  "intensity": "medium" },
    "integrityChecks":  { "enabled": true },
    "polymorphism":     { "enabled": true },
    "honeypots":        { "enabled": false },
    "decompilerPoison": { "enabled": false },
    "antiDebug":        { "enabled": false, "decoy": false }
  }
}
```

## Keys

- `seedFile` — path to the secret keyfile (same as `--seed-file`). `null` → non-deterministic builds.
  See [entropy-and-seeding](entropy-and-seeding.md).
- `llm.provider` — `"off"` or `"claude"`. See [llm-provider](llm-provider.md).
- `features.<tier>.enabled` — on/off for each tier (`ToggleOptions`).
- `features.rename.keepPublic` — keep public/family API names unchanged (default `true`).
- `features.controlFlow.opaquePredicates` — `false` makes the control-flow pass a no-op (default `true`).
- `features.llmMisdirection.intensity` — `"low"` (2 decoy types), `"medium"` (5), `"high"` (12); any
  other value is treated as `"medium"` (`MisdirectionOptions.DecoyTypeCount`).
- `features.antiDebug.decoy` — `false` (default) installs only the benign read-and-discard probe;
  `true` degrades to decoy on detection (see [anti-debug](../tiers/anti-debug.md)). CLI:
  `--anti-debug-decoy` (implies `--anti-debug`).

## Defaults

| Default on (behavior-safe) | Default off (higher-risk / dual-use) |
|---|---|
| `rename`, `stringEncryption`, `controlFlow`, `llmMisdirection`, `integrityChecks`, `polymorphism` | `honeypots`, `decompilerPoison`, `antiDebug` |

## Option types

`ToggleOptions` (base, `enabled`), `RenameOptions` (+`keepPublic`), `ControlFlowOptions`
(+`opaquePredicates`), `MisdirectionOptions` (+`intensity`, with the `DecoyTypeCount` mapping above),
`AntiDebugOptions` (+`decoy`).

## Related docs

[cli](cli.md) · [architecture](architecture.md) · per-tier docs under [`../tiers/`](../tiers/)
