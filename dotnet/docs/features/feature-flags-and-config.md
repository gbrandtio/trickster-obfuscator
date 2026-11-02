# Feature: feature flags and config

Every tier lives behind an independent flag. Nothing is hardwired into the pipeline; a disabled
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
    "rename":           { "enabled": true,  "keepPublic": true, "exclude": [] },
    "stringEncryption": { "enabled": true },
    "controlFlow":      { "enabled": true,  "opaquePredicates": true, "flatten": true, "indirectDispatch": true },
    "llmMisdirection":  { "enabled": true,  "intensity": "medium" },
    "integrityChecks":  { "enabled": true },
    "polymorphism":     { "enabled": true },
    "honeypots":        { "enabled": false },
    "decompilerPoison": { "enabled": false },
    "antiDebug":        { "enabled": false, "decoy": false },
    "virtualization":   { "enabled": false },
    "rasp":             { "enabled": false, "liveDebuggerCheck": true, "nativeDebuggerCheck": true, "profilerCheck": true, "periodicIntegrityCheck": true, "integrityIntervalMs": 5000 }
  }
}
```

## Keys

- `seedFile`: path to the secret keyfile (same as `--seed-file`). `null` → non-deterministic builds.
  See [entropy-and-seeding](entropy-and-seeding.md).
- `llm.provider`: `"off"` or `"claude"`. See [llm-provider](llm-provider.md).
- `features.<tier>.enabled`: on/off for each tier (`ToggleOptions`).
- `features.rename.keepPublic`: keep public/family/protected-internal API names unchanged (default `true`).
- `features.rename.exclude`: list of symbol names or `*` wildcard patterns to skip during renaming (default `[]`; CLI `--rename-exclude`).
- `features.controlFlow.opaquePredicates`: prepend an always-true entry predicate + decoy `throw` (default `true`).
- `features.controlFlow.flatten`: flatten eligible methods into a shuffled `switch` state machine (default `true`; CLI `--no-flatten`).
- `features.controlFlow.indirectDispatch`: route intra-module static calls through static delegate fields (default `true`; CLI `--no-indirect-dispatch`).
- `features.llmMisdirection.intensity`: `"low"` (2 decoy types), `"medium"` (5), `"high"` (12); any
  other value is treated as `"medium"` (`MisdirectionOptions.DecoyTypeCount`).
- `features.antiDebug.decoy`: `false` (default) installs only the benign read-and-discard probe;
  `true` degrades to decoy on detection (see [anti-debug](../tiers/anti-debug.md)). CLI:
  `--anti-debug-decoy` (implies `--anti-debug`).
- `features.virtualization.enabled`: compile eligible static integer/boolean methods into custom VM bytecode (default `false`; CLI `--virtualize` / `--no-virtualize`).
- `features.rasp`: runtime self-protection (default off; CLI `--rasp` / `--no-rasp`). Re-checks during
  execution and degrades guarded methods to inert fakes on detection. Sub-options:
  `liveDebuggerCheck` (managed `Debugger.IsAttached`/`IsLogging`, default `true`),
  `nativeDebuggerCheck` (Windows `IsDebuggerPresent`/`CheckRemoteDebuggerPresent` + Linux
  `/proc/self/status` `TracerPid`; default `true`; CLI `--no-rasp-native`),
  `profilerCheck` (CLR profiler env vars, default `true`),
  `periodicIntegrityCheck` (throttled whole-image re-hash; requires the `integrity` tier; default
  `true`), and `integrityIntervalMs` (default `5000`; CLI `--rasp-interval`). See
  [rasp](../tiers/rasp.md).

## Defaults

| Default on (behavior-safe) | Default off (higher-risk / dual-use) |
|---|---|
| `rename`, `stringEncryption`, `controlFlow`, `llmMisdirection`, `integrityChecks`, `polymorphism` | `honeypots`, `decompilerPoison`, `antiDebug`, `virtualization`, `rasp` |

## Option types

`ToggleOptions` (base, `enabled`), `RenameOptions` (+`keepPublic`, +`exclude`), `ControlFlowOptions`
(+`opaquePredicates`, +`flatten`, +`indirectDispatch`), `MisdirectionOptions` (+`intensity`, with the `DecoyTypeCount` mapping above),
`AntiDebugOptions` (+`decoy`), `RaspOptions` (+`liveDebuggerCheck`, +`nativeDebuggerCheck`,
+`profilerCheck`, +`periodicIntegrityCheck`, +`integrityIntervalMs`).

## Related docs

[cli](cli.md) · [architecture](architecture.md) · per-tier docs under [`../tiers/`](../tiers/)
