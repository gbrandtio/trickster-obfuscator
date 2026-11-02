# Trickster

Trickster is an obfuscator that protects your compiled code's intellectual property. It
rewrites a built binary so it is much harder to read, decompile, and reverse-engineer, and
it can plant decoys and false descriptions so that AI-assisted analysis reaches confident but
wrong conclusions.

Trickster only ever modifies **your own binary**. It does not generate prompt-injection
payloads or anything meant to hijack a third party's AI agent.

> [!WARNING]  
> The target of this library is to make LLM-powered reverse engineering as expensive as
> possible both for LLMs and human malicius actors.
> With that being said, obfuscation should not be treated as a security measure, and users
> of this library must be aware that a determined operator can obfuscate any binary, no matter
> how the obfuscation was produced.

## Implementations

| Platform | Location | Status |
|---|---|---|
| .NET (Mono.Cecil, `net9.0`) | [`dotnet/`](dotnet/) | Available |

## Features

Trickster organizes its protections into **tiers**. The tiers below are the common model
shared by every language implementation; each platform applies them with its own toolchain.
Some are on by default, others are opt-in.

| Tier | Default | What it does |
|---|---|---|
| Rename | on | Renames types/members to hostile names while preserving your public API and exclusions. |
| String encryption | on | Encrypts string literals and injects a decryptor so literals never appear in the binary. |
| Control flow | on | Obscures execution with indirect dispatch, block flattening, and opaque predicates. |
| LLM misdirection | on | Plants domain-named decoy types with false descriptions to mislead AI-assisted analysis. |
| Integrity checks | on | Embeds a tamper canary and a whole-image hash guard. |
| Polymorphism | on | Varies the output per build (or per seed) so no two builds look alike. |
| Honeypots | off | Plants fake secrets with a leak canary to detect exfiltration. |
| Decompiler poison | off | Adds constructs that break or confuse common decompilers. |
| LLM bloat | off | Injects many inert decoy types to make the binary token-expensive for an LLM to analyze. |
| Anti-debug | off | Detects attached debuggers, optionally degrading to inert decoy behavior. |
| Virtualization | off | Compiles eligible methods into custom VM bytecode. |
| RASP | off | Runtime self-protection: re-checks for debuggers/profilers/tampering during execution. |

Feature availability and exact behavior can vary by platform. See each implementation's
README for specifics (e.g. [`dotnet/README.md`](dotnet/README.md)).

## License

Trickster is released under the [MIT License](LICENSE).
