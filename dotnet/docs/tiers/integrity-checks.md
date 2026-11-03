# Tier: integrity (integrity self-check)

Injects a module-initializer guard that verifies both a baked canary hash and a whole-image SHA-256
digest of the assembly file on disk at load time, so any byte modification or automated rewrite trips
it.

## At a glance

| | |
|---|---|
| CLI flag | on by default. `--no-integrity` turns it off. `--integrity` forces it on. `--integrity-distributed <n>` and `--integrity-probabilistic` add the optional hardening below. |
| Config key | `features.integrityChecks` (`enabled`, `distributedChecks`, `probabilisticResponse`) |
| Default | **on** |
| Source | `src/Trickster.DotNet/Transforms/IntegrityCheckTransform.cs`, `src/Trickster.DotNet/AssemblyObfuscator.cs`, `src/Trickster.DotNet/Runtime/CecilExtensions.cs`, `src/Trickster.DotNet/Runtime/WholeImageVerify.cs` |

## Purpose / threat model

A tool that strips other tiers or patches instructions works by modifying the assembly binary. This
tier is the **integrity + polymorphism** layer: a load-time check that verifies both an internal
canary and the SHA-256 hash of the entire `.dll` file on disk, throwing `InvalidOperationException`
if any byte in the file was altered.

## How it works

1. **Baked canary self-consistency check:** At build time the pass generates 48 random canary bytes and
   computes `expectedCanary = Base64(SHA256(canary))`. At load time the guard reconstructs the 48-byte
   array in IL, hashes it with `SHA256.HashData`, compares the Base64 result to `expectedCanary`, and
   throws `InvalidOperationException` on mismatch. This check works even when the assembly is loaded
   from memory (`Assembly.Location` is empty).
2. **Whole-image SHA-256 check:** The pass embeds a 36-byte private resource named
   `Trickster.Integrity`. After `AssemblyObfuscator` writes the final assembly to disk, it locates the
   resource inside the written file, records the 4-byte file offset of the 32-byte digest slot in
   bytes `0..4`, zeroes bytes `4..36`, computes `SHA256.HashData` over the entire file, and writes the
   32-byte digest into bytes `4..36`. At load time, when `Assembly.Location` is non-empty, the guard
   reads the assembly file from disk, zeroes the 32-byte digest slot at the recorded offset, hashes the
   entire byte buffer with `SHA256.HashData`, and throws `InvalidOperationException` if it does not
   match the 32-byte digest in `Trickster.Integrity`.

The guard is wired into the module initializer via
`CecilExtensions.GetOrCreateModuleInitializer().PrependCall(...)`, so it runs when the assembly loads.
The whole-image check is emitted as a shared `static bool` verifier
(`Runtime/WholeImageVerify.cs`); the load guard throws on `false`, and the [`rasp`](rasp.md) tier
reuses the same method for its periodic runtime re-check.

## Optional hardening

Two opt-in sub-options build on the load-time guard. Both are off by default, so the default output
is unchanged.

- **`distributedChecks` (int, default `0`).** Adds that many extra inline whole-image checks. Each check
  is placed at the start of a random method, so a single NOP cannot disable all of them. Each check
  calls the same `WholeImageVerify` method as the load guard. With `probabilisticResponse` off, a failed
  check throws `InvalidOperationException` at the check site.
- **`probabilisticResponse` (bool, default `false`).** Changes what a failed check does. The check sets a
  shared tamper flag and lets the real body run. Eligible methods then return an inert fake value once
  the flag is set. The failure appears far from the check site. Eligible methods are the same value- and
  `string`-returning methods that the [`rasp`](rasp.md) tier diverts. Public methods are skipped when
  `rename.keepPublic` is true.

Use `distributedChecks` alone for more coverage. Add `probabilisticResponse` when a throw at the check
site would reveal where the check is.

## Configuration

- `--no-integrity` to disable, `--integrity` to force on.
- `--integrity-distributed <n>`: scatter `n` extra checks (`n` must be zero or more).
- `--integrity-probabilistic`: degrade eligible methods to inert fakes on tamper. Also turns on the
  tier.
- Config: `{ "features": { "integrityChecks": { "enabled": true, "distributedChecks": 0, "probabilisticResponse": false } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only integrity
```

## Behavior preservation / safety

An unmodified obfuscated assembly passes both checks at module load and runs normally. Both behavior
preservation and single-byte file-tampering detection are covered by automated tests.

## Limitations

- A determined attacker who edits the binary can locate and patch out the module-initializer call
  itself alongside their modifications.
- When an assembly is loaded purely from memory (`Assembly.Location` is empty), only the 48-byte
  canary check runs.
- Every distributed check calls the same verifier method. Patching that one method disables all of
  them at once.

## Related docs

[polymorphism](polymorphism.md) · [rasp](rasp.md) · [architecture](../features/architecture.md)
