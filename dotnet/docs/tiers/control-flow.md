# Tier: controlflow (control-flow obfuscation)

Adds an always-true opaque predicate at each method entry; the never-taken branch is a decoy `throw`.

## At a glance

| | |
|---|---|
| CLI flag | on by default; `--no-controlflow` to disable |
| Config key | `features.controlFlow` (`enabled`, `opaquePredicates`) |
| Default | **on** (`opaquePredicates: true`) |
| Source | `src/Trickster.DotNet/Transforms/ControlFlowTransform.cs` |

## Purpose / threat model

Straight-line IL reads like pseudocode. Inserting a predicate whose outcome is not statically obvious,
guarding a decoy path, is the **entangled-decoy** idea in its simplest form: to decide which path is
live, an analyst must reason about the predicate rather than delete an annotation. It also breaks
naive linear disassembly.

## How it works

For every method with a body (static constructors are skipped), the pass calls `SimplifyMacros()`,
then prepends, before the original first instruction:

```
ldc.i4 n; ldc.i4 n; mul; ldc.i4 n; sub; ldc.i4.2; rem; ldc.i4.0; ceq   // (n*n - n) % 2 == 0  -> always true
brtrue  <original first instruction>
newobj  System.Exception::.ctor()                                      // decoy, never executed
throw
```

`n` is a random constant from the entropy source. `(n*n - n)` is always even, so the predicate is
always true and control always reaches the real body; the `throw` is unreachable. The stack is empty
at method entry, so the inserted sequence is verifiable. `OptimizeMacros()` runs afterward.

## Configuration

- `--no-controlflow` — turn the tier off.
- Config: `features.controlFlow.opaquePredicates = false` also makes the pass a no-op.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only controlflow
```

## Behavior preservation / safety

The empty-stack-at-entry design keeps the IL verifiable. Because insertions happen before the original
first instruction and use `Instruction` references, existing exception-handler region boundaries keep
pointing at the same instructions. A dedicated test obfuscates a method containing a `try/catch` and
confirms identical results.

## Limitations

- v1 adds one predicate at entry; it does not flatten whole-method control flow or virtualize methods
  (virtualization is planned for v2). A reverser who runs the code is unaffected.

## Related docs

[architecture](../features/architecture.md) · [string-encryption](string-encryption.md) · [cli](../features/cli.md)
