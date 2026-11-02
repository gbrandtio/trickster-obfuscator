# Trickster (.NET)

Trickster is an obfuscator for .NET assemblies. It uses Mono.Cecil to rewrite the IL of a compiled
DLL after it is built. Its purpose is to protect a library author's own intellectual property (IP).

It also includes an LLM misdirection layer. The goal of that layer is to make LLM-assisted reverse
engineering produce confident but wrong conclusions.

## Defensive scope

Trickster is a defensive tool. The misdirection layer places decoys and false descriptions only inside
the author's own binary, to mislead someone who analyzes that binary. It does **not** generate payloads
for a third party's AI agent, and it does not write text that tries to make an agent ignore its
instructions, run commands, or send data somewhere. `MisdirectionGuard`
(`src/Trickster.Core/Llm/MisdirectionGuard.cs`) enforces this on all LLM output and all built-in corpus
text; it is a pattern filter, not a complete classifier. See
[docs/features/misdirection-guard.md](docs/features/misdirection-guard.md).

## Requirements

- .NET 9 SDK. All projects target `net9.0`.

## Build and test

```sh
cd dotnet
dotnet build
dotnet test
```

The test project (`tests/Trickster.DotNet.Tests`) obfuscates the sample library with each tier and
checks that the sample program prints the same result, that string literals are removed, that seeded
builds are reproducible, that the honeypot canary is emitted, and that the guard rejects payload text.

## Documentation

Each tier and each cross-cutting feature has its own document under `docs/`. Start with
[architecture](docs/features/architecture.md) for the pipeline and the robustness model.

### Tiers (`docs/tiers/`)

| Tier | Default | Document |
|---|---|---|
| `rename` | on | [rename.md](docs/tiers/rename.md): rename types/members to hostile names, keep public API and exclusions |
| `strings` | on | [string-encryption.md](docs/tiers/string-encryption.md): encrypt literals with multi-byte key schedule, inject a decryptor |
| `controlflow` | on | [control-flow.md](docs/tiers/control-flow.md): indirect delegate dispatch, basic-block flattening, and entry opaque predicate |
| `misdirection` | on | [llm-misdirection.md](docs/tiers/llm-misdirection.md): domain-named decoy types with false descriptions |
| `integrity` | on | [integrity-checks.md](docs/tiers/integrity-checks.md): module-initializer canary and whole-image SHA-256 guard |
| `polymorphism` | on | [polymorphism.md](docs/tiers/polymorphism.md): per-build variation / seed selection |
| `honeypots` | off | [honeypots.md](docs/tiers/honeypots.md): fake secrets + leak canary |
| `poison` | off | [decompiler-poison.md](docs/tiers/decompiler-poison.md): decompiler-hostile decoy members |
| `llmbloat` | off | [llm-bloat.md](docs/tiers/llm-bloat.md): many inert decoy types that make the binary token-expensive to analyze with an LLM (passive, author's-own-binary only) |
| `antidebug` | off | [anti-debug.md](docs/tiers/anti-debug.md): benign `Debugger.IsAttached` probe; optional `--anti-debug-decoy` degrade-to-decoy |
| `virtualize` | off | [virtualization.md](docs/tiers/virtualization.md): compile integer/boolean methods into custom VM bytecode |
| `rasp` | off | [rasp.md](docs/tiers/rasp.md): runtime self-protection — re-check for debuggers/profilers/tampering during execution, degrade to inert fakes |

### Features (`docs/features/`)

- [architecture.md](docs/features/architecture.md): layers, run flow, shared name generator, pass order, robustness model, honest limits.
- [cli.md](docs/features/cli.md): the `trickster dotnet obfuscate` command, every flag, `--only`/`--off`, exit codes.
- [feature-flags-and-config.md](docs/features/feature-flags-and-config.md): the `TricksterConfig` JSON schema, defaults, sub-options.
- [entropy-and-seeding.md](docs/features/entropy-and-seeding.md): CSPRNG vs secret seed, reproducible builds, Kerckhoffs's principle.
- [llm-provider.md](docs/features/llm-provider.md): the Claude provider, offline fallback, and what is (and is not) sent.
- [misdirection-guard.md](docs/features/misdirection-guard.md): the defensive-scope boundary and the validator.

## Project layout

| Path | Contents |
|---|---|
| `src/Trickster.Cli` | Command-line entry point (`Program.cs`). |
| `src/Trickster.Core` | Config model, composition framework (modules, registry, chain, artifact blackboard), entropy source, LLM interface, `MisdirectionGuard`. |
| `src/Trickster.DotNet` | Mono.Cecil engine, tier transforms + modules, and the obfuscation engine. |
| `src/Trickster.Llm.Claude` | Anthropic API provider. |
| `tests/Trickster.DotNet.Tests` | xUnit tests. |
| `samples/` | `SampleLibrary` and `SampleConsumer` used for manual checks. |
