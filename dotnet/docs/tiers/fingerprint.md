# Tier: fingerprint (per-build leak-tracing fingerprint)

Embeds a unique identifier in each build. If a copy leaks, the author can read the identifier back
and trace the copy to the build that produced it, and to a licensee if one was set.

## At a glance

| | |
|---|---|
| CLI flag | off by default. `--fingerprint` turns it on. `--fingerprint-id <id>` turns it on and sets the customer id. |
| Config key | `features.fingerprint` (`enabled`, `customerId`) |
| Default | **off** |
| Recover | `trickster dotnet fingerprint-verify <assembly>` |
| Source | `src/Trickster.DotNet/Transforms/FingerprintTransform.cs` (`FingerprintReader` is in the same file) |

## Purpose / threat model

Licensed or distributed binaries can leak. A fingerprint links a leaked copy to the build that made
it. This is a forensic aid. It does not stop copying, and it does not limit how the binary is used.

## How it works

The build id has two parts. When a customer id is set, the id is `<customerId>:<nonce>`. Otherwise the
id is the nonce alone. The nonce is 8 random bytes from the shared entropy source, written as 16
lowercase hex characters. With a seed file, the nonce is reproducible, so a seeded build gets the same
id each time.

The id is stored in two places:

1. **Encrypted resource (the recoverable channel).** A private embedded resource named
   `Trickster.Fingerprint` holds `[key length][key][ciphertext]`. The key is 8 random bytes. The
   ciphertext uses the same position-rolling XOR as the [`resources`](resource-encryption.md) tier.
2. **Constant field (a second copy).** An inert public static literal string field holds the same
   blob, base64 encoded.

The `fingerprint-verify` command reads the encrypted resource, reverses the cipher, and prints the id.
It does not read the constant field.

The id also appears in the run output and in the result object:

- The CLI prints `Fingerprint (recover with 'fingerprint-verify'): <id>`.
- `--map` writes the id to the JSON result in the `Fingerprint` field.

The tier runs at order band 22, after honeypots and before constants and string encryption.

## Configuration

- `--fingerprint`: enable the tier with no customer id.
- `--fingerprint-id <id>`: enable the tier and record a licensee or customer id.
- Config: `{ "features": { "fingerprint": { "enabled": true, "customerId": "acme" } } }`.

## Example

```sh
dotnet … dotnet obfuscate MyLib.dll -o MyLib.obf.dll --fingerprint-id acme
dotnet … dotnet fingerprint-verify MyLib.obf.dll
# Fingerprint: acme:<16 hex characters>
```

## Behavior preservation / safety

The tier adds one resource and one type. It does not change any method body, so program output is
unchanged. Tests check that the id is embedded, that `FingerprintReader` returns the same id as the
run result, and that a seeded build produces the same id on every run.

## Limitations

- **The key ships in the assembly.** Each build stores its cipher key next to the ciphertext, so anyone
  who reads the resource can recover the id. The fingerprint is for tracing, not for secrecy.
- **Removable.** A reverser who finds and deletes the `Trickster.Fingerprint` resource and the constant
  field removes the fingerprint.
- **The second copy does not help recovery.** `fingerprint-verify` reads only the encrypted resource.
  If the resource is removed, the command reports no fingerprint, even though the constant field still
  holds the blob.
- **The customer id is not hidden.** Treat it as visible to anyone who reads the assembly. Do not use a
  value you consider secret.
- **Not a signature.** The id does not prove who built or signed the file.

## Related docs

[resource-encryption](resource-encryption.md) · [polymorphism](polymorphism.md) · [cli](../features/cli.md)
