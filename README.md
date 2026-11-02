# Trickster

Trickster is an obfuscator that protects your compiled code's intellectual property. It
rewrites a built binary so it is much harder to read, decompile, and reverse-engineer, and
it can plant decoys and false descriptions so that AI-assisted analysis reaches confident but
wrong conclusions.

Trickster only ever modifies **your own binary**. It does not generate prompt-injection
payloads or anything meant to hijack a third party's AI agent.

## Implementations

| Platform | Location | Status |
|---|---|---|
| .NET (Mono.Cecil, `net9.0`) | [`dotnet/`](dotnet/) | Available |

## Quick start (.NET)

Requires the **.NET 9 SDK**.

```sh
cd dotnet
dotnet build
dotnet run --project src/Trickster.Cli -- dotnet obfuscate MyLib.dll -o MyLib.obf.dll
```

See [`dotnet/README.md`](dotnet/README.md) for the full feature list, CLI options, and docs.

## License

See [LICENSE](LICENSE).
