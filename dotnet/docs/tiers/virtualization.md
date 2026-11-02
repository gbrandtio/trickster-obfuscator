# Tier: virtualize (method virtualization)

Compiles eligible integer and boolean methods into a custom per-build randomized 2-word bytecode
array (`int[]`) encrypted with a per-build key, and replaces each method body with a stub that invokes
an injected stack-machine interpreter.

## At a glance

| | |
|---|---|
| CLI flag | `--virtualize` (off by default); `--no-virtualize` to disable |
| Config key | `features.virtualization` (`enabled`) |
| Default | **off** |
| Source | `src/Trickster.DotNet/Transforms/MethodVirtualizationTransform.cs` |

## Purpose / threat model

Standard .NET CIL instructions (`add`, `mul`, `brtrue`, `blt`) are understood natively by every .NET
decompiler. Method virtualization replaces CIL with a custom instruction set whose opcode numbers and
XOR key are randomized on every build using the run's `EntropySource`. A decompiler inspecting a
virtualized method sees only an `int[]` array passed to an interpreter method; understanding the
method statically requires first reverse-engineering the per-build interpreter and decoding its
bytecode table.

## How it works

1. **Opcode table generation:** At build time the pass assigns each of the 24 VM operations (`Nop`,
   `Ldc`, `Ldarg`, `Starg`, `Ldloc`, `Stloc`, `Dup`, `Pop`, `Add`, `Sub`, `Mul`, `Div`, `Rem`, `And`,
   `Or`, `Xor`, `Neg`, `Ceq`, `Cgt`, `Clt`, `Br`, `Brtrue`, `Brfalse`, `Ret`) a distinct random integer
   in `[10, 10000)` and draws a random 32-bit `codeKey` from `context.Entropy`.
2. **Method eligibility:** Static methods without exception handlers, generic parameters, or `this`
   whose parameters, local variables, and return type are 32-bit-compatible integers or booleans
   (`int`, `bool`, `byte`, `sbyte`, `short`, `ushort`) and whose CIL instructions belong to the
   supported arithmetic, bitwise, comparison, local/argument, and branch subset are selected. Two-input
   conditional branches (`beq`, `bne.un`, `blt`, `ble`, `bgt`, `bge`) are decomposed into a comparison
   op (`Ceq`, `Clt`, `Cgt`) followed by `Brtrue` or `Brfalse`.
3. **Bytecode encoding:** Every VM instruction occupies two `int` slots (`code[pc] = opcode ^ codeKey`,
   `code[pc + 1] = operand ^ codeKey`). Branch targets are word indices (`targetInstruction * 2`).
4. **Interpreter and stub injection:** One internal static interpreter class is injected with a
   `public static int Execute(int[] code, int[] args, int localCount)` method that allocates a 64-slot
   evaluation stack and `localCount` locals, decodes `(op, operand)` pairs in a loop, and executes each
   handler. Each virtualized method body is replaced with a stub that constructs its `int[]` bytecode
   and `int[]` argument array and calls `Execute`.
5. **Pipeline synergy:** Because `virtualization` runs before `controlflow` and `rename`, the injected
   interpreter and its call sites are subsequently flattened, routed through indirect delegate
   dispatch, guarded with opaque predicates, and renamed to confusable identifiers.

## Configuration

- `--virtualize` to enable, `--no-virtualize` to disable.
- `--only virtualize` or `--off virtualize`.
- Config: `{ "features": { "virtualization": { "enabled": true } } }`.

## Example

```sh
dotnet src/Trickster.Cli/bin/Debug/net9.0/trickster.dll \
  dotnet obfuscate MyLib.dll -o MyLib.obf.dll --virtualize
```

## Behavior preservation / safety

Only static integer/boolean methods whose full instruction sequence maps cleanly to the VM instruction
set are virtualized; any method with unsupported opcodes, reference types, or exception handlers is
left untouched. Behavior-preservation and tier tests confirm identical results.

## Limitations

- Interpretation adds runtime overhead compared to native JIT-compiled CIL, so this tier is opt-in.
- Reference-returning methods, instance methods, and methods with `try/catch` blocks are skipped.

## Related docs

[control-flow](control-flow.md) · [architecture](../features/architecture.md) · [polymorphism](polymorphism.md)

