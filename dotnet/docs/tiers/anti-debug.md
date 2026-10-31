# Tier: antidebug

Installs a benign module-initializer probe that reads `Debugger.IsAttached` and discards the result.

## At a glance

| | |
|---|---|
| CLI flag | `--anti-debug` (off by default); `--anti-debug-decoy` adds degrade-to-decoy (implies `--anti-debug`) |
| Config key | `features.antiDebug` (`enabled`, `decoy`) |
| Default | **off** (and `decoy` **off**) |
| Source | `src/Trickster.DotNet/Transforms/AntiDebugTransform.cs` |

## Purpose / threat model

Dynamic analysis (running the code under a debugger) is the accepted escape hatch from the static
tiers. This tier is a measured, **opt-in** nod to raising that cost. It is deliberately dual-use-safe:
it takes no harmful action, does not crash, does not affect the user's machine, and does not attempt
AV/EDR evasion.

## How it works

The pass injects a static method that calls `System.Diagnostics.Debugger.get_IsAttached`, wired into
the module initializer so it runs at load.

**Benign mode (`decoy` off, default):** the probe `pop`s the result and returns. The detection result
is discarded — the probe only raises the cost of casual inspection.

**Degrade-to-decoy mode (`decoy` on):** the probe stores the result (sampled once, at load) into a
shared static flag. Eligible methods get an entry guard — `if (observed) { decoy(); return <fake>; }`
— so that, when a debugger was attached at load, they divert into an inert decoy routine and return a
fake value instead of running their real body. To keep the fake value guaranteed non-crashing, only
methods returning a **value type** (diverted to `default(T)`) or **`string`** (diverted to a fake
literal) are eligible. Reference-returning methods — including `Task`/async and iterator methods — are
left untouched, so the decoy can never hand a caller a `null` to fault on. Also skipped: the assembly
entry point, async/iterator state-machine methods, and the same cases `rename` skips (ctors,
accessors, virtuals, P/Invoke, interfaces, and — when `keepPublic` — the public API).

## Configuration

- `--anti-debug` to enable the benign probe.
- `--anti-debug-decoy` to enable the probe **and** degrade-to-decoy (implies `--anti-debug`).
- Config: `{ "features": { "antiDebug": { "enabled": true, "decoy": true } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --anti-debug
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --anti-debug-decoy
```

## Behavior preservation / safety

With no debugger attached, behavior is identical to the un-obfuscated program — in benign mode the
probe reads and discards one boolean; in decoy mode the guard's `observed` flag is `false`, so every
method runs its real body. Behavior-preservation tests pass with both modes enabled. The decoy divert
is itself bounded: it only alters the program's own value/`string` return values, takes no destructive
action, touches no machine state, and performs no sandbox/AV/EDR evasion.

## Limitations

- **It does not block debugging.** The benign mode only reads `Debugger.IsAttached` and discards it.
- **Decoy mode is a one-shot, load-time sample.** `Debugger.IsAttached` is read once in the module
  initializer; a debugger attached to an already-running process is **not** detected.
- **Decoy mode never crashes a caller.** It deliberately guards only value- and `string`-returning
  methods (so the fake is `default(T)` or a fake literal, never `null`); reference/`Task`/iterator
  returns are left untouched by design.
- It remains opt-in and off by default, within the project's defensive, non-harmful scope.

## Related docs

[integrity-checks](integrity-checks.md) · [architecture](../features/architecture.md)
