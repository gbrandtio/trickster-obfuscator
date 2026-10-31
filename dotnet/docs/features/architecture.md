# Feature: architecture and pipeline

How Trickster is organized, how a run flows, and the robustness model the tiers implement.

## Source

- `src/Trickster.Core/ITransform.cs`, `ObfuscationPipeline.cs`, `IObfuscationContext.cs`
- `src/Trickster.DotNet/DotNetObfuscationContext.cs`, `AssemblyObfuscator.cs`

## Layers

Trickster separates a language-agnostic core from the .NET engine, so other languages could be added
as sibling engines later.

- **`Trickster.Core`** — `ITransform<TContext>`, `ObfuscationPipeline<TContext>`, the
  `IObfuscationContext` surface (`Config`, `Entropy`, `Llm`, `Logger`), the config model, the entropy
  source, the LLM interface, and `MisdirectionGuard`. No Cecil dependency.
- **`Trickster.DotNet`** — the Mono.Cecil engine. `DotNetObfuscationContext` implements
  `IObfuscationContext` and adds the loaded `AssemblyDefinition` / `Module`, the `RenameMap`, the
  `Canaries` list, and the shared `NameGenerator` (`Names`). Each tier is an `ITransform`.
- **`Trickster.Llm.Claude`** — optional Anthropic provider.
- **`Trickster.Cli`** — the command-line front end.

## Run flow

`AssemblyObfuscator.Obfuscate(input, output, config, llm, logger)`:

1. Build a `DefaultAssemblyResolver` with the input's directory on its search path.
2. Read the assembly with `ReadingMode.Immediate` and `InMemory = true` (no file lock).
3. Pick the `EntropySource` via `MutationEngine.CreateEntropy(config)`.
4. Construct `DotNetObfuscationContext` (this creates the one shared `NameGenerator`).
5. Build the transform list from the feature flags and run them through the pipeline.
6. `assembly.Write(output)`.
7. Return `ObfuscationResult(OutputPath, RenamedSymbols, Canaries, RenameMap)`.

### Shared name generator

Every transform uses `context.Names`, a **single** `NameGenerator` per run. This guarantees generated
identifiers are unique across the whole module — critical because several transforms emit types into
the same (empty) namespace, and two independently-generated identical names would produce duplicate
types and an unloadable assembly.

### Pass order

Only enabled transforms are constructed. The order is: `misdirection`, `honeypots`, `strings`,
`controlflow`, `rename`, `integrity`, `poison`, `antidebug`. Decoys go in first so later passes treat
them like real code; the sealing passes (integrity/poison/antidebug) go last. Polymorphism is not a
pass — it only selects the entropy source.

## Robustness model (weakest → strongest)

The order reflects intended cost to a reverse engineer; it is not a measured result.

1. **Plain text** — all tiers off; names, strings, and logic readable.
2. **Names** — `rename` removes most readable identifiers (public API kept by default).
3. **Entangled decoys** — `misdirection`, `honeypots`, `controlflow`: false paths and descriptions
   that must be reasoned about, not just deleted.
4. **Information removal** — `strings`: literal text is absent from the static form. (Indirect
   dispatch is not implemented in v1.)
5. **Integrity and polymorphism** — `integrity` detects some edits to its canary data; `polymorphism`
   makes each build different.
6. **Method virtualization** — planned for v2; not implemented.

## Honest limits

- Obfuscation raises cost; it does not make code unbreakable.
- The tiers are strongest against **static** analysis, including LLM analysis of the static form.
- **Dynamic analysis is the accepted escape hatch**: the code must run, so a reverser who runs it can
  observe real values with a debugger, tracer, or memory dump.
- `antidebug` does not block debugging (its optional `decoy` mode only diverts the program's own
  value/`string` returns to inert fakes, and only when a debugger is attached at load); `integrity`
  checks only its own canary; `strings` uses a single-byte XOR with the key in the same assembly.

## Related docs

[feature-flags-and-config](feature-flags-and-config.md) · [cli](cli.md) · [entropy-and-seeding](entropy-and-seeding.md)
