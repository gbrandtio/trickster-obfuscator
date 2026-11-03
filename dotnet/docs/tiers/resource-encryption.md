# Tier: resources (embedded resource encryption)

Encrypts the assembly's embedded resources and redirects the author's own
`Assembly.GetManifestResourceStream(string)` calls through an injected decrypting method. The resource
bytes are absent from the static assembly.

## At a glance

| | |
|---|---|
| CLI flag | off by default. `--encrypt-resources` turns it on. No CLI flag turns it off, so use config. |
| Config key | `features.resourceEncryption` (`enabled`, `exclude`) |
| Default | **off** |
| Source | `src/Trickster.DotNet/Transforms/ResourceEncryptionTransform.cs`, `src/Trickster.DotNet/Runtime/ResourceCipher.cs` |

## Purpose / threat model

Embedded resources often hold data files, templates, or other content. A decompiler can extract them
with one command. This tier raises the cost of that step. A static tool or an LLM that reads the
assembly sees ciphertext instead of the file. This is an **information-removal** tier, like
[`strings`](string-encryption.md).

This is obfuscation, not a cryptographic boundary. The key ships in the same assembly. A reverser who
reads the shim can decrypt every encrypted resource. Do not store a secret in an embedded resource and
rely on this tier to protect it.

## How it works

1. **Select.** Every embedded resource is a target, except:
   - Trickster's own resources (`Trickster.Fingerprint` and `Trickster.Integrity`).
   - `*.resources` blobs (ResourceManager/resx). These are read outside
     `GetManifestResourceStream(string)`, so the shim cannot decrypt them transparently; they are
     skipped automatically with a build-time warning.
   - Names that match a pattern in `exclude`. Patterns use `*` (any run of characters) and `?` (one
     character). A pattern must match the whole resource name.
2. **Encrypt.** One 16-byte key is drawn from the shared entropy source. It is used for every encrypted
   resource. Each target is replaced with its ciphertext under the same name and attributes. The
   cipher is the position-rolling XOR `out[i] = in[i] ^ key[i % 16] ^ ((i * 31) & 0xFF)`.
3. **Shim.** An injected static method, `Stream Shim(Assembly, string)`, calls the original
   `GetManifestResourceStream` first. If the name is one of the encrypted names, the shim copies the
   stream to memory, applies the same cipher, and returns the plaintext stream. For any other name, it
   returns the original stream unchanged. The encrypted names are compiled into the shim as string
   comparisons.
4. **Redirect.** Each `call` or `callvirt` to `System.Reflection.Assembly::GetManifestResourceStream(string)`
   in the assembly is changed to call the shim. The shim takes the same arguments, so the calling code
   does not change.

The tier runs at order band 33, after string encryption and before virtualization. It runs before
`integrity`, so the integrity resource is never encrypted.

## Configuration

- `--encrypt-resources`: enable the tier.
- Config: `{ "features": { "resourceEncryption": { "enabled": true, "exclude": [ "Assets.*" ] } } }`.
  Use `exclude` to leave a resource in the clear.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --encrypt-resources
```

## Behavior preservation / safety

Code that loads a resource with `Assembly.GetManifestResourceStream(string)` receives the same bytes as
before. The behavior tests build the sample library with this tier on. They check that the plaintext
no longer appears in the file and that the sample still returns the same payload at run time.

## Limitations

- **Only the `GetManifestResourceStream(string)` overload is redirected.** Other lookups are not
  changed. These include the `GetManifestResourceStream(Type, string)` overload and calls made from
  other assemblies. Those calls would receive ciphertext, so leave such resources in the clear via
  `exclude`. (`ResourceManager`/resx `*.resources` blobs are detected and skipped automatically.)
- **The key ships in the assembly.** Anyone who reads the shim can recover the key. Dynamic analysis
  sees the decrypted resource whenever the program loads it.
- **Resource names stay visible.** The names are in the assembly manifest. The shim also compares
  against the names as plain string literals, because the string tier runs before this tier.

## Related docs

[string-encryption](string-encryption.md) · [fingerprint](fingerprint.md) · [integrity-checks](integrity-checks.md) · [cli](../features/cli.md)
