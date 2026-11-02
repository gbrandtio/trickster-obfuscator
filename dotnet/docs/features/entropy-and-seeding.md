# Feature: entropy and seeding

The single random source every transform draws from, and how reproducible builds work.

## Source

`src/Trickster.Core/Entropy/EntropySource.cs`, `src/Trickster.DotNet/Polymorphism/MutationEngine.cs`

## Two modes

`EntropySource` has two modes exposing the same API (`NextInt`, `NextBytes`, `NextBool`,
`NextUInt64`, `Pick`):

- **Non-deterministic** (`CreateNonDeterministic`): backed by the OS CSPRNG
  (`RandomNumberGenerator`). Every build differs, and nothing in the open-source algorithm lets an
  attacker reproduce the output. `IsDeterministic` is `false`.
- **Deterministic** (`FromSeedFile` / `FromSeedBytes`): a SHA-256 keystream where successive blocks are
  `SHA256(seed || counter)`. The seed is the SHA-256 of the supplied bytes, so any non-empty file works
  as a seed (`FromSeedFile` throws `ArgumentException` if the file is empty). Reproducible, and
  `IsDeterministic` is `true`. (Not a weak LCG.)

## Seed selection (MutationEngine)

`MutationEngine.CreateEntropy(config)` applies this precedence:

1. `seedFile` present → `FromSeedFile` (reproducible from a secret). **Always wins.**
2. else polymorphism on → `CreateNonDeterministic`.
3. else (polymorphism off, no seed) → `FromSeedBytes(canonical)`, a fixed public constant (`"Trickster-v1"`).

## Kerckhoffs's principle

Trickster is open source, so its naming and transform algorithms are public. Security therefore must
**not** depend on the secrecy of the algorithm; it rests on the secrecy of your `--seed-file`. With a
secret seed you get reproducible builds whose output an attacker cannot reproduce without the seed.
The canonical-seed mode is reproducible but public, so it provides repeatability, not secrecy.

## Reproducible builds

```sh
dotnet … dotnet obfuscate MyLib.dll -o a.dll --seed-file build.seed
dotnet … dotnet obfuscate MyLib.dll -o b.dll --seed-file build.seed
cmp a.dll b.dll   # identical
```

Keep `build.seed` out of source control. Tests cover both the reproducible (same seed → identical)
and non-deterministic (no seed → differs) paths.

## Related docs

[polymorphism](../tiers/polymorphism.md) · [feature-flags-and-config](feature-flags-and-config.md)
