# Tier: polymorphism

Selects the random source for a build, making each build structurally different unless you pin a seed.
This tier has no code transform of its own.

## At a glance

| | |
|---|---|
| CLI flag | on by default; `--off polymorphism` to disable; `--seed-file <path>` to pin |
| Config key | `features.polymorphism` (`enabled`), plus top-level `seedFile` |
| Default | **on** |
| Source | `src/Trickster.DotNet/Polymorphism/MutationEngine.cs`, `src/Trickster.Core/Entropy/EntropySource.cs` |

## Purpose / threat model

If every release were byte-identical, a reverse engineer could build one de-obfuscation script and
reuse it, or crowd-source a cracker. Per-build variation means a tool built for one release does not
transfer to the next. This is the **integrity + polymorphism** layer alongside the integrity check.

## How it works

`MutationEngine.CreateEntropy(config)` chooses the `EntropySource` that every pass draws from, with
this precedence:

1. **A `--seed-file` / `seedFile` is present** → `EntropySource.FromSeedFile(...)`. Reproducible build
   from a secret. **This always wins**, even when polymorphism is off.
2. **No seed, polymorphism on** → `EntropySource.CreateNonDeterministic()` (OS CSPRNG); every build
   differs.
3. **No seed, polymorphism off** → a fixed canonical seed; output is identical for everyone.

Because every transform pulls its random choices (names, keys, predicate constants, decoy counts)
from this one source, pinning the seed pins the entire build. See
[entropy-and-seeding](../features/entropy-and-seeding.md) for the generator details and the
Kerckhoffs rationale (security rests on the secret seed, never on the open-source algorithm).

## Configuration

- `--seed-file <path>` — secret keyfile for a reproducible build.
- `--off polymorphism` (or `features.polymorphism.enabled = false`) — use the canonical seed when no
  seed file is given.

## Example

```sh
# Reproducible: same seed -> byte-identical output
dotnet … dotnet obfuscate MyLib.dll -o a.dll --seed-file build.seed
dotnet … dotnet obfuscate MyLib.dll -o b.dll --seed-file build.seed   # a.dll == b.dll
```

## Behavior preservation / safety

Polymorphism changes only which random values are chosen, not what the passes do; it cannot by itself
alter program behavior. Tests cover both the reproducible (same seed → identical) and non-deterministic
(no seed → differs) paths.

## Limitations

- The canonical-seed mode (polymorphism off, no seed) is reproducible but **not** secret — anyone can
  reproduce it from the public source. Use a secret `--seed-file` when you need reproducibility with
  security.

## Related docs

[entropy-and-seeding](../features/entropy-and-seeding.md) · [integrity-checks](integrity-checks.md)
