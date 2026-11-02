# Tier: rasp (runtime application self-protection)

Injects a self-contained monitor that re-checks for debuggers, profilers, and whole-image tampering
**during execution** (not only at load) and diverts eligible methods to inert fake return values
once a check trips.

## At a glance

| | |
|---|---|
| CLI flag | `--rasp` (off by default); `--no-rasp` to disable; `--no-rasp-native`; `--rasp-interval <ms>` |
| Config key | `features.rasp` (`enabled`, `liveDebuggerCheck`, `nativeDebuggerCheck`, `profilerCheck`, `periodicIntegrityCheck`, `integrityIntervalMs`) |
| Default | **off** |
| Source | `src/Trickster.DotNet/Transforms/RaspTransform.cs`, `src/Trickster.DotNet/Runtime/WholeImageVerify.cs` |

## Purpose / threat model

The [`integrity`](integrity-checks.md) and [`antidebug`](anti-debug.md) tiers check **once, at load**:
a debugger attached afterward, or a file patched after load, is never noticed. RASP closes that gap
by moving the checks **into execution**. Each guarded method, on entry, calls a shared
`Evaluate()` that re-samples for an analysis environment; the first positive result latches a shared
`Compromised` flag, after which guarded methods return a provably inert fake instead of their real
body.

It stays within the project's **detection-only, non-harmful scope**: it takes no destructive action,
touches no machine state, does not crash the host, and performs no AV/EDR/sandbox evasion.

## How it works

The pass snapshots eligible target methods, injects one internal `RaspMonitor` type (confusable
name), and prepends a guard to each target. `Evaluate()` runs these checks (each enabled
independently), short-circuiting on the first hit:

1. **Live managed debugger (`liveDebuggerCheck`):** re-reads `Debugger.IsAttached` and
   `Debugger.IsLogging()` on every call (unlike `antidebug`, which samples once at load).
2. **Native debugger (`nativeDebuggerCheck`):** OS-gated and wrapped in try/catch so it never faults
   an unsupported host:
   - **Windows** (`RuntimeInformation.IsOSPlatform(OSPlatform.Windows)`): injected P/Invoke to
     `kernel32!IsDebuggerPresent` and `CheckRemoteDebuggerPresent(GetCurrentProcess(), out bool)` —
     catches native debuggers (WinDbg/x64dbg) that the managed flag misses.
   - **Linux** (`IsOSPlatform(Linux)`): reads `/proc/self/status` and matches `TracerPid:\s*[1-9]`
     (a ptrace-based debugger such as gdb/lldb/strace).
   - **macOS:** not covered; falls back to the managed + profiler checks.
3. **Profiler/hook (`profilerCheck`):** detects an attached CLR profiler via the standard environment
   variables (`CORECLR_ENABLE_PROFILER` / `COR_ENABLE_PROFILING` == `1`, or a non-empty
   `CORECLR_PROFILER`).
4. **Periodic integrity (`periodicIntegrityCheck`):** re-verifies the whole-image SHA-256 against the
   `Trickster.Integrity` resource, **throttled** to roughly once per `integrityIntervalMs`
   (`Environment.TickCount64`; best-effort — the timestamp is not synchronized across threads, so
   concurrent callers may occasionally re-hash within one window). Reuses the shared `WholeImageVerify` method emitted by the
   [`integrity`](integrity-checks.md) tier, so it requires that tier; if `integrity` is disabled the
   pass logs a warning and skips this check (the others still run).

On entry each guarded method runs `if (Evaluate()) return <decoy>;`. To keep the fake provably
non-crashing, only methods returning a **value type** (diverted to `default(T)`) or **`string`**
(diverted to a fake literal `"svc_" + <12 lowercase hex chars>`) are eligible; the same cases
`rename`/`antidebug` skip are skipped here too (entry point, `[AsyncStateMachine]`/
`[IteratorStateMachine]`, constructors, accessors, virtual/abstract/override, P/Invoke, interfaces,
methods with `out`/`ref`/pointer parameters — whose caller would read an unwritten argument on the
decoy path — and, when `keepPublic`, public/family/`protected internal`). The shared whole-image verifier is
also excluded so `Evaluate() → periodic-integrity → VerifyImage()` cannot recurse.

Because the tier runs **last** in the pipeline (after `integrity`), the `Trickster.Integrity`
resource already exists for it to re-verify.

## Configuration

- `--rasp` to enable; `--no-rasp` to disable.
- `--no-rasp-native`: keep RASP but drop the native (Windows/Linux) debugger probes.
- `--rasp-interval <ms>`: minimum milliseconds between whole-image re-hashes (default `5000`).
- `--only rasp` / `--off rasp`.
- Config: `{ "features": { "rasp": { "enabled": true, "liveDebuggerCheck": true, "nativeDebuggerCheck": true, "profilerCheck": true, "periodicIntegrityCheck": true, "integrityIntervalMs": 5000 } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --rasp
# pair with the load-time guard for the periodic re-check:
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only integrity,rasp
```

## Behavior preservation / safety

With no debugger, profiler, or tampering, `Evaluate()` returns false and every guarded method runs
its real body — output is identical to the un-obfuscated program. Behavior-preservation tests run
with the tier enabled (alone and with `integrity`); dedicated tests verify the monitor/guards are
installed, that latching `Compromised` diverts a guarded method to a non-null fake while the public
entry still completes, and that post-load file tampering is caught by the periodic re-check.

## Limitations

- **Removable, like every in-binary protection.** The monitor is IL in the shipped assembly; a
  determined reverser can neuter `Evaluate()`, strip the guard prologues, or force `Compromised`
  false, and nothing cascades. Its value is **cost/deterrence** (amplified by per-build
  [polymorphism](polymorphism.md)); genuine anti-removal needs an external anchor (OS code signing,
  server-side checks, attestation).
- **No background thread:** checks fire only when guarded methods are called, so a program that
  stops calling them stops re-checking.
- **Native detection is Windows + Linux only** (macOS falls back to the managed/profiler checks),
  and `Debugger.IsAttached` sees only self-announcing managed debuggers.
- The periodic integrity re-check is skipped for memory-only loads (empty `Assembly.Location`) and
  requires the `integrity` tier.

## Related docs

[anti-debug](anti-debug.md) · [integrity-checks](integrity-checks.md) · [polymorphism](polymorphism.md) · [architecture](../features/architecture.md)
