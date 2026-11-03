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
    "constants":        { "enabled": true,  "intensity": "medium" },
    "resourceEncryption": { "enabled": false, "exclude": [] },
    "fingerprint":      { "enabled": false, "customerId": "" },
    "stringEncryption": { "enabled": true },
    "controlFlow":      { "enabled": true,  "opaquePredicates": true, "flatten": true, "indirectDispatch": true },
    "llmMisdirection":  { "enabled": true,  "intensity": "medium" },
    "integrityChecks":  { "enabled": true,  "distributedChecks": 0, "probabilisticResponse": false },
    "polymorphism":     { "enabled": true },
    "honeypots":        { "enabled": false },
    "decompilerPoison": { "enabled": false },
    "antiDebug":        { "enabled": false, "decoy": false },
    "virtualization":   { "enabled": false },
    "rasp":             { "enabled": false, "liveDebuggerCheck": true, "nativeDebuggerCheck": true, "profilerCheck": true, "periodicIntegrityCheck": true, "integrityIntervalMs": 5000, "analysisToolCheck": false, "sandboxCheck": false },
    "llmBloat":         { "enabled": false, "intensity": "medium", "maxTypes": 500 }
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
  `true`), and `integrityIntervalMs` (default `5000`; CLI `--rasp-interval`). Two opt-in checks are
  also available: `analysisToolCheck` (known RE tool process names, default `false`; CLI
  `--rasp-analysis`) and `sandboxCheck` (single-processor hosts, default `false`; CLI `--rasp-sandbox`).
  The native probes cover Windows, Linux, and macOS. See [rasp](../tiers/rasp.md).
- `features.constants`: integer-literal obfuscation (default on; CLI `--no-constants` /
  `--constants-intensity`). Sub-option `intensity`: `"low"` (about 35% of literals), `"medium"` (about
  70%, the default), or `"high"` (100%). Any other value is treated as `"medium"`. See
  [constants](../tiers/constants.md).
- `features.resourceEncryption`: embedded-resource encryption (default off; CLI `--encrypt-resources`).
  Sub-option `exclude`: resource names or `*`/`?` patterns to leave in the clear (default `[]`). See
  [resource-encryption](../tiers/resource-encryption.md).
- `features.fingerprint`: per-build leak-tracing fingerprint (default off; CLI `--fingerprint` /
  `--fingerprint-id <id>`). Sub-option `customerId`: optional licensee id recorded in the fingerprint
  (default `""`). Recover a fingerprint with `trickster dotnet fingerprint-verify <assembly>`. See
  [fingerprint](../tiers/fingerprint.md).
- `features.integrityChecks.distributedChecks`: number of extra whole-image checks scattered across
  random methods (default `0`; CLI `--integrity-distributed <n>`).
- `features.integrityChecks.probabilisticResponse`: on tamper, degrade eligible methods to inert fake
  returns instead of throwing at the check site (default `false`; CLI `--integrity-probabilistic`). See
  [integrity-checks](../tiers/integrity-checks.md).
- `features.llmBloat`: anti-LLM-analysis volume inflation (default off; CLI `--llm-bloat` /
  `--no-llm-bloat`). Injects many inert decoy types so the author's own binary is token-expensive
  to analyze when decompiled and fed to an LLM. Sub-options: `intensity` (`"low"` = 25 types,
  `"medium"` = 75, `"high"` = 200; any other value → `"medium"`) and `maxTypes` (hard ceiling,
  default `500`; the resolved count is `min(intensity, maxTypes)`). Passive and defensive — emits
  no text/payload and targets no third-party agent. See [llm-bloat](../tiers/llm-bloat.md).

## Defaults

| Default on (behavior-safe) | Default off (higher-risk / dual-use) |
|---|---|
| `rename`, `constants`, `stringEncryption`, `controlFlow`, `llmMisdirection`, `integrityChecks`, `polymorphism` | `resourceEncryption`, `fingerprint`, `honeypots`, `decompilerPoison`, `antiDebug`, `virtualization`, `rasp`, `llmBloat` |

## Option types

`ToggleOptions` (base, `enabled`), `RenameOptions` (+`keepPublic`, +`exclude`), `ControlFlowOptions`
(+`opaquePredicates`, +`flatten`, +`indirectDispatch`), `MisdirectionOptions` (+`intensity`, with the `DecoyTypeCount` mapping above),
`AntiDebugOptions` (+`decoy`), `ConstantOptions` (+`intensity`, with the `RewriteChance` mapping above),
`ResourceEncryptionOptions` (+`exclude`), `FingerprintOptions` (+`customerId`), `IntegrityOptions`
(+`distributedChecks`, +`probabilisticResponse`), `RaspOptions` (+`liveDebuggerCheck`, +`nativeDebuggerCheck`,
+`profilerCheck`, +`periodicIntegrityCheck`, +`integrityIntervalMs`, +`analysisToolCheck`, +`sandboxCheck`), `LlmBloatOptions`
(+`intensity`, +`maxTypes`, with the `ResolvedTypeCount` mapping above).

## Related docs

[cli](cli.md) · [architecture](architecture.md) · per-tier docs under [`../tiers/`](../tiers/)
