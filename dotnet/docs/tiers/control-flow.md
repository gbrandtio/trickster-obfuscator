# Tier: controlflow (control-flow obfuscation)

Routes intra-module static calls through delegate fields, flattens eligible method bodies into a
shuffled `switch` state machine, and prepends an always-true opaque predicate at method entry.

## At a glance

| | |
|---|---|
| CLI flag | on by default; `--no-controlflow` to disable; `--no-flatten` / `--no-indirect-dispatch` |
| Config key | `features.controlFlow` (`enabled`, `opaquePredicates`, `flatten`, `indirectDispatch`) |
| Default | **on** (`opaquePredicates: true`, `flatten: true`, `indirectDispatch: true`) |
| Source | `src/Trickster.DotNet/Transforms/ControlFlowTransform.cs` |

## Purpose / threat model

Straight-line IL with direct `call` targets reads like pseudocode. This tier combines three
mechanisms:

1. **Indirect call dispatch** hides direct intra-module call-graph edges behind static `Func<...>` and
   `Action<...>` delegate fields initialized in a helper static constructor.
2. **Whole-method control-flow flattening** partitions eligible methods into zero-stack basic blocks
   and dispatches them inside a single `switch (state ^ mask)` loop with shuffled block order and state
   IDs.
3. **Entry opaque predicates** guard each method with an arithmetic predicate whose outcome is not
   statically obvious and whose never-taken branch is a decoy `throw`.

## How it works

1. **Indirect dispatch (`indirectDispatch`):** For every intra-module `call` targeting an eligible
   non-generic static method (up to 4 parameters, no by-ref/pointer types), the pass creates a static
   `readonly` delegate field (`Action` or `Func<...>`) on an injected helper type and initializes it in
   that helper type's `.cctor` via `ldftn` + `newobj`. (Private target methods are widened to `internal`
   so the helper `.cctor` can bind them.) Each call site is rewritten in place to store arguments into
   temporaries, load the delegate field, reload arguments, and invoke `callvirt Invoke`.
2. **Control-flow flattening (`flatten`):** For each non-constructor method without exception handlers,
   the pass computes the CIL evaluation stack depth before every instruction and partitions the body
   into zero-stack basic blocks (merging any range crossed by an intra-expression branch). When a method
   has at least two blocks, it allocates a local `int state`, assigns each block a shuffled case index
   XORed with a random `mask`, physically shuffles the blocks, and rewrites inter-block jumps and
   fallthroughs to update `state` and jump to the `switch` dispatcher.
3. **Opaque predicate (`opaquePredicates`):** For every method with a body (static constructors
   skipped), the pass calls `SimplifyMacros()` and prepends, before the first instruction:

```
ldc.i4 n; ldc.i4 n; mul; ldc.i4 n; sub; ldc.i4.2; rem; ldc.i4.0; ceq   // (n*n - n) % 2 == 0  -> always true
brtrue  <original first instruction>
newobj  System.Exception::.ctor()                                      // decoy, never executed
throw
```

`n` is a random integer in `[3, 100000)` from the entropy source. `(n*n - n)` is always even, so the predicate is
always true and control always reaches the real body; the `throw` is unreachable. The stack is empty
at method entry, so the inserted sequence is verifiable. `OptimizeMacros()` runs afterward.

## Configuration

- `--no-controlflow`: turn the entire tier off.
- `--no-flatten`: disable basic-block flattening while keeping indirect dispatch and opaque predicates.
- `--no-indirect-dispatch`: disable delegate call routing while keeping flattening and opaque predicates.
- Config: `features.controlFlow` supports `enabled`, `opaquePredicates`, `flatten`, and `indirectDispatch`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only controlflow
```

## Behavior preservation / safety

The zero-stack basic-block closure guarantees that flattened `switch` targets are always entered with an
empty evaluation stack, and methods with `try/catch` regions skip flattening so exception-handler
boundaries continue pointing at their exact instructions (while still receiving the entry opaque
predicate). Dedicated tests verify exception-handling preservation, `switch` emission, and delegate
dispatch.

## Limitations

- Methods with exception handlers (`try/catch/finally`) or only a single zero-stack block skip
  flattening and receive the entry opaque predicate instead.
- Indirect dispatch covers static non-generic methods with up to 4 parameters; instance, virtual, and
  generic calls are left as direct calls.
- For translating CIL instructions into a custom bytecode interpreter, enable the companion
  [`virtualize`](virtualization.md) tier.

## Related docs

[virtualization](virtualization.md) · [architecture](../features/architecture.md) · [string-encryption](string-encryption.md) · [cli](../features/cli.md)
