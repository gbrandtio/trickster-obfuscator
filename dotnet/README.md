# Trickster (.NET)

Trickster is an obfuscator for .NET assemblies. You point it at a compiled DLL and it
rewrites the IL in place , making the binary much harder to read,
decompile, and reverse-engineer. It is meant to protect your own code's intellectual
property.

This obfuscator is specifically designed to counter (as much as possible) the recent trend
of reverse engineering powered by LLMs (or make it more expensive).

> [!WARNING]  
> The target of this library is to make LLM-powered reverse engineering as expensive as
> possible both for LLMs and human malicius actors.
> With that being said, obfuscation should not be treated as a security measure, and users
> of this library must be aware that a determined operator can obfuscate any binary, no matter
> how the obfuscation was produced.


## Defensive scope

Trickster only ever modifies your own binary. The misdirection layer writes decoys and
false descriptions into that binary to mislead someone analyzing it. It does **not** generate
prompt-injection payloads or anything meant to hijack a third party's AI agent.
`MisdirectionGuard` (`src/Trickster.Core/Llm/MisdirectionGuard.cs`) enforces this on every
piece of generated and built-in text. See
[docs/features/misdirection-guard.md](docs/features/misdirection-guard.md).

## Quick start

Requires the **.NET 9 SDK**.

```sh
cd dotnet
dotnet build
```

Obfuscate an assembly with the default protections:

```sh
dotnet run --project src/Trickster.Cli -- dotnet obfuscate MyLib.dll -o MyLib.obf.dll
```

Common options:

```sh
# Turn specific tiers on
... obfuscate MyLib.dll -o out.dll --integrity --honeypots --virtualize

# Run only a chosen set of tiers
... obfuscate MyLib.dll -o out.dll --only rename,strings,controlflow

# Reproducible build from a secret seed
... obfuscate MyLib.dll -o out.dll --seed-file secret.key

# Embed a leak-tracing fingerprint, then recover it from a leaked build
... obfuscate MyLib.dll -o out.dll --fingerprint-id acme
... fingerprint-verify out.dll
```

By default the public API surface is preserved (`--keep-public`), so callers of your library
keep working. Run `... dotnet obfuscate` with no arguments to print full usage, or see
[docs/features/cli.md](docs/features/cli.md) for every flag.

## Features

Tiers marked **on** run by default; the rest are opt-in.

| Tier | Default | What it does |
|---|---|---|
| `rename` | on | Renames types/members to hostile names; keeps the public API and your exclusions. |
| `constants` | on | Rewrites integer literals into equivalent inline arithmetic. |
| `strings` | on | Encrypts string literals and injects a decryptor. |
| `resources` | off | Encrypts embedded resources and redirects `GetManifestResourceStream(string)` calls through a decrypting shim. |
| `fingerprint` | off | Embeds a per-build leak-tracing id, recoverable with `fingerprint-verify`. |
| `controlflow` | on | Indirect dispatch, basic-block flattening, and an opaque entry predicate. |
| `misdirection` | on | Domain-named decoy types with false descriptions (anti-LLM). |
| `integrity` | on | Module-initializer canary and a whole-image SHA-256 guard. Optional distributed and probabilistic hardening. |
| `polymorphism` | on | Per-build variation / seed selection. |
| `honeypots` | off | Fake secrets plus a leak canary. |
| `poison` | off | Decompiler-hostile decoy members. |
| `llmbloat` | off | Many inert decoy types that make the binary token-expensive for an LLM to analyze. |
| `antidebug` | off | Benign `Debugger.IsAttached` probe; optional degrade-to-decoy mode. |
| `virtualize` | off | Compiles eligible integer/boolean methods into custom VM bytecode. |
| `rasp` | off | Runtime self-protection: re-checks for debuggers/profilers/tampering and degrades to inert fakes. Optional analysis-tool and sandbox checks. |

## Documentation

Each tier and cross-cutting feature has its own doc under `docs/`. Start with
[architecture](docs/features/architecture.md) for the pipeline and the robustness model.

- Tiers: [docs/tiers/](docs/tiers/) — one document per tier above.
- Features: [cli](docs/features/cli.md), [config & feature flags](docs/features/feature-flags-and-config.md),
  [entropy & seeding](docs/features/entropy-and-seeding.md), [LLM provider](docs/features/llm-provider.md),
  [misdirection guard](docs/features/misdirection-guard.md).

## Build and test

```sh
cd dotnet
dotnet build
dotnet test
```

The tests obfuscate the sample library with each tier and check that the sample program still
prints the same result, that string literals are gone, that seeded builds are reproducible,
that the honeypot canary is emitted, and that the guard rejects payload text.

## Project layout

| Path | Contents |
|---|---|
| `src/Trickster.Cli` | Command-line entry point. |
| `src/Trickster.Core` | Config model, composition framework, entropy source, LLM interface, `MisdirectionGuard`. |
| `src/Trickster.DotNet` | Mono.Cecil engine and the tier transforms. |
| `src/Trickster.Llm.Claude` | Anthropic API provider. |
| `tests/Trickster.DotNet.Tests` | xUnit tests. |
| `samples/` | `SampleLibrary` and `SampleConsumer` for manual checks. |
