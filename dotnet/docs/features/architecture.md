# Feature: architecture and pipeline

How Trickster is organized, how a run flows, and the robustness model the tiers implement.

## Source

- `src/Trickster.Core/ITransform.cs`, `ObfuscationPipeline.cs`, `IObfuscationContext.cs`
- `src/Trickster.DotNet/DotNetObfuscationContext.cs`, `AssemblyObfuscator.cs`

## Layers

Trickster separates a language-agnostic core from the .NET engine, so other languages could be added
as sibling engines later.

- **`Trickster.Core`**: `ITransform<TContext>`, `ObfuscationPipeline<TContext>`, the
  `IObfuscationContext` surface (`Config`, `Entropy`, `Llm`, `Logger`), the config model, the entropy
  source, the LLM interface, and `MisdirectionGuard`. No Cecil dependency.
- **`Trickster.DotNet`**: the Mono.Cecil engine. `DotNetObfuscationContext` implements
  `IObfuscationContext` and adds the loaded `AssemblyDefinition` / `Module`, the `RenameMap`, the
  `Canaries` list, `PreservedDecoyTypes`, `WholeImageDigestMarker`, and the shared `NameGenerator`
  (`Names`). Each tier is an `ITransform`.
- **`Trickster.Llm.Claude`**: optional Anthropic provider.
- **`Trickster.Cli`**: the command-line front end.

## Run flow

`AssemblyObfuscator.Obfuscate(inputPath, outputPath, config, llm, logger)`:

1. Build a `DefaultAssemblyResolver` with the input's directory on its search path.
2. Read the assembly with `ReadingMode.Immediate` and `InMemory = true` (no file lock).
3. Pick the `EntropySource` via `MutationEngine.CreateEntropy(config)`.
4. Construct `DotNetObfuscationContext` (this creates the one shared `NameGenerator`).
5. Build the transform list from the feature flags and run them through the pipeline.
6. `assembly.Write(outputPath)`, then if `IntegrityCheckTransform` registered a
   `WholeImageDigestMarker`, compute and stamp the whole-image SHA-256 digest into the written
   `Trickster.Integrity` embedded resource.
7. Return `ObfuscationResult(OutputPath, RenamedSymbols, Canaries, RenameMap)`, where `RenamedSymbols` is `context.RenameMap.Count` (the count of renamed types, methods, and fields).

### Shared name generator

Every transform uses `context.Names`, a **single** `NameGenerator` per run. This guarantees generated
identifiers are unique across the whole module, which is critical because several transforms emit types into
the same (empty) namespace, and two independently-generated identical names would produce duplicate
types and an unloadable assembly.

### Pass order

Only enabled transforms are constructed. The order is: `misdirection`, `honeypots`, `strings`,
`virtualize`, `controlflow`, `rename`, `integrity`, `poison`, `antidebug`, `rasp`. Decoys go in first so later
passes treat them like real code; structural passes (`strings`, `virtualize`, `controlflow`, `rename`)
run next; the sealing passes (`integrity`, `poison`, `antidebug`, `rasp`) go last. `rasp` runs after
`integrity` so the `Trickster.Integrity` resource exists for its periodic re-check. Polymorphism is
not a pass; it only selects the entropy source.

## Robustness model (weakest → strongest)

The order reflects intended cost to a reverse engineer; it is not a measured result.

1. **Plain text**: all tiers off; names, strings, and logic readable.
2. **Names**: `rename` removes most readable identifiers (public API and configured exclusions kept by default).
3. **Entangled decoys**: `misdirection`, `honeypots`, `controlflow`: false paths, flattened state machines, and descriptions
   that must be reasoned about rather than deleted.
4. **Information removal**: `strings` and `controlflow` (`indirectDispatch`): literal text is encrypted with a multi-byte rolling key schedule, and intra-module static calls are routed through static delegate fields.
5. **Integrity and polymorphism**: `integrity` verifies a baked canary and the whole-image SHA-256 of the assembly file on disk; `polymorphism`
   makes each build different.
   - **Runtime self-protection**: `rasp` re-runs debugger/profiler/whole-image checks *during* execution (not only at load) and degrades guarded methods to inert fakes on detection, closing the one-shot-at-load gap of `integrity`/`antidebug`.
6. **Method virtualization**: `virtualize` compiles eligible integer and boolean methods into custom per-build randomized bytecode executed by an injected stack-machine interpreter.

## Honest limits

- Obfuscation raises cost; it does not make code unbreakable.
- The tiers are strongest against **static** analysis, including LLM analysis of the static form.
- **Dynamic analysis is the accepted escape hatch**: the code must run, so a reverser who runs it can
  observe real values with a debugger, tracer, or memory dump.
- `antidebug` does not block debugging (its optional `decoy` mode only diverts the program's own
  value/`string` returns to inert fakes, and only when a debugger is attached at load); `integrity`
  verifies the baked canary and file image at load time but can still be patched out by a reverser who
  removes the guard; `strings` ships the decryptor and per-literal 8-byte keys in the same assembly.
- `rasp` re-checks during execution, but — like every in-binary tier — it is itself IL in the shipped
  assembly: a reverser can neuter its `Evaluate()`, strip the guards, or force its flag false. It
  raises cost/deterrence (amplified by polymorphism); it is not an external root of trust.

## Related docs

[feature-flags-and-config](feature-flags-and-config.md) · [cli](cli.md) · [entropy-and-seeding](entropy-and-seeding.md)
