# Tier: integrity (integrity self-check)

Injects a module-initializer guard that verifies a baked canary hash at load time, so automated
rewrites tend to trip it.

## At a glance

| | |
|---|---|
| CLI flag | on by default; `--no-integrity` to disable; `--integrity` to force on |
| Config key | `features.integrityChecks` (`enabled`) |
| Default | **on** |
| Source | `src/Trickster.DotNet/Transforms/IntegrityCheckTransform.cs`, `src/Trickster.DotNet/Runtime/CecilExtensions.cs` |

## Purpose / threat model

A tool that strips other tiers usually works by rewriting the assembly. This tier is the
**integrity + polymorphism** layer: a self-consistency check whose baked data an automated rewrite is
likely to perturb, tripping the guard at load.

## How it works

At build time the pass generates 48 random canary bytes and computes
`expected = Base64(SHA256(canary))`. It injects a static guard type whose method:

1. reconstructs the canary byte array in IL;
2. calls `SHA256.HashData` then `Convert.ToBase64String`;
3. compares the result to the baked `expected` string via `string.op_Equality`;
4. returns on match, or `throw`s `InvalidOperationException` on mismatch.

The guard is wired into the module initializer via
`CecilExtensions.GetOrCreateModuleInitializer().PrependCall(...)`, so it runs when the assembly loads.

## Configuration

- `--no-integrity` to disable, `--integrity` to force on.
- Config: `{ "features": { "integrityChecks": { "enabled": true } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only integrity
```

## Behavior preservation / safety

The guard only reads and hashes baked constants and compares strings; it adds no behavior to normal
code paths. The behavior tests run with this tier on and confirm the assembly still loads and runs.

## Limitations

- **Self-consistency only.** The check covers its own canary data, not a hash of the whole file. It
  detects some tampering but a determined attacker can locate and remove the guard. Whole-image
  tamper-proofing is a documented later refinement.

## Related docs

[polymorphism](polymorphism.md) · [architecture](../features/architecture.md)
