# Tier: constants (numeric constant obfuscation)

Rewrites integer literals into equivalent inline arithmetic, so magic numbers, table sizes, and flag
masks no longer appear as plain constants in the static form.

## At a glance

| | |
|---|---|
| CLI flag | on by default. `--no-constants` turns it off. `--constants-intensity` takes `low`, `medium`, or `high`. |
| Config key | `features.constants` (`enabled`, `intensity`) |
| Default | **on**, with `intensity` set to `medium` |
| Source | `src/Trickster.DotNet/Transforms/ConstantObfuscationTransform.cs` |

## Purpose / threat model

An integer literal is a static anchor. A table size, a bit mask, or a magic number tells an analyst
what the code does. This is an **information-removal** tier for numbers. It hides each value inside a
computed expression. It does not stop a reverser who runs the code.

## How it works

The pass visits every method body. It first runs `SimplifyMacros()`, so every integer literal uses the
same form. It then looks at each `ldc.i4` and `ldc.i8` instruction. For each one, it draws a random
number from the shared entropy source. The literal is rewritten only when that number falls under the
rewrite chance for the chosen intensity.

The rewrite changes the instruction in place, so any branch that targets it stays valid. A 32-bit
literal `v` becomes one of three identities, chosen at random:

- `(v ^ k) ^ k`: push `v ^ k`, push `k`, then `xor`.
- `k + (v - k)`: push `k`, push `v - k`, then `add`.
- `k - (k - v)`: push `k`, push `k - v`, then `sub`.

A 64-bit literal uses the `xor` form with a 64-bit key. Each identity returns `v` exactly, using
two's complement arithmetic. The pass ends with `OptimizeMacros()`.

Rewrite chance by intensity:

| `intensity` | Literals rewritten |
|---|---|
| `low` | about 35% |
| `medium` (default) | about 70% |
| `high` | 100% |

Any other value is treated as `medium`.

The tier runs at order band 25, before string encryption (band 30). That order means it never touches
the byte arrays that the string tier emits.

## Configuration

- `--no-constants`: turn the tier off.
- `--constants-intensity <low|medium|high>`: set the rewrite rate.
- Config: `{ "features": { "constants": { "enabled": true, "intensity": "medium" } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only constants
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --constants-intensity high
```

## Behavior preservation / safety

Each identity is exact, so the value on the evaluation stack never changes. Behavior-preservation
tests run the sample program with this tier enabled. A separate test checks that the sample's
instruction count grows when every literal is rewritten (`intensity` set to `high`).

## Limitations

- The three identities are simple patterns. A deobfuscator that knows them can undo the rewrite.
- A reverser who runs the code sees the real values.
- Only `ldc.i4` and `ldc.i8` are rewritten. Floating-point literals (`ldc.r4`, `ldc.r8`) are not
  touched.

## Related docs

[string-encryption](string-encryption.md) · [control-flow](control-flow.md) · [cli](../features/cli.md)
