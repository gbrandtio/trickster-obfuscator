# Tier: strings (string encryption)

Replaces every string literal with an encrypted byte array and a call to an injected decryptor, so
the plaintext is absent from the static form of the assembly.

## At a glance

| | |
|---|---|
| CLI flag | on by default; `--no-strings` to disable |
| Config key | `features.stringEncryption` (`enabled`) |
| Default | **on** |
| Source | `src/Trickster.DotNet/Transforms/StringEncryptionTransform.cs`, `src/Trickster.DotNet/Runtime/StringCipher.cs` |

## Purpose / threat model

Hardcoded strings (messages, format strings, keys, URLs) are the single richest source of meaning in
a static view. This is the **information-removal** tier: a static analyzer — including an LLM reading
the static assembly — sees ciphertext plus a decrypt call, not the text. To recover it the analyst
must run the code (dynamic analysis), which is the accepted, higher-cost escape hatch.

## How it works

One decryptor type (confusable name, static) is injected with a method
`string Decrypt(byte[] data, byte key)` whose IL XORs each byte with the key and returns
`Encoding.UTF8.GetString(data)`.

For every method body, the pass collects `ldstr` instructions with a non-empty operand. If a method
has none, it is left untouched. Otherwise `SimplifyMacros()` is called (so short branches cannot
overflow when the body grows), and each `ldstr` is rewritten **in place**: the instruction's opcode
becomes `ldc.i4 <length>` (mutating in place keeps any branch that targeted the `ldstr` valid), then
the byte-array construction (`newarr`, and `dup`/`ldc`/`ldc`/`stelem.i1` per byte), the key, and the
`call` to the decryptor are inserted after it. `OptimizeMacros()` re-shortens branches afterward.

`StringCipher.Encrypt` (build-time) applies the same single-byte XOR; the key is random per literal
(1–255).

## Configuration

- `--no-strings` — turn the tier off.
- Config: `{ "features": { "stringEncryption": { "enabled": true } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --only strings
strings MyLib.obf.dll | grep "my secret message"   # no match
```

## Behavior preservation / safety

Covered by tests: the sample program prints identical output with the tier on, and a plaintext-removal
test confirms a known literal no longer appears (checked in both UTF-16 and UTF-8, since .NET stores
literals in the UTF-16 user-string heap). The in-place `ldstr` rewrite and macro handling were added
specifically to fix branch-target and short-branch bugs found during testing.

## Limitations

- Single-byte XOR per literal. This defeats casual scanning, not cryptanalysis: the decryptor and the
  per-literal key both ship in the same assembly, so a reverser who runs the code recovers everything.
  A multi-byte key schedule is a documented later refinement.

## Related docs

[architecture](../features/architecture.md) · [llm-misdirection](llm-misdirection.md) · [cli](../features/cli.md)
