# Feature: CLI

The `trickster` command-line front end: one verb, `dotnet obfuscate`.

## Source

`src/Trickster.Cli/Program.cs`

## Invocation

After `dotnet build`:

```sh
dotnet src/Trickster.Cli/bin/Debug/net9.0/trickster.dll dotnet obfuscate <input.dll> -o <output.dll> [options]
```

The first two tokens must be `dotnet obfuscate`. If fewer than two arguments are passed, or the first
two tokens are not `dotnet obfuscate`, the usage text is printed (exiting with `1` when no arguments
are given, and `0` otherwise).

## Flags

| Flag | Effect |
|---|---|
| `<input.dll>` | Input assembly. Required (first positional). |
| `-o, --output <path>` | Output path. Defaults to overwriting the input. |
| `--config <path>` | Load settings from a JSON file. CLI flags are applied after the file. |
| `--seed-file <path>` | Secret keyfile for a reproducible build. Always honored when present. |
| `--map <path>` | Write a JSON result: output path, renamed-symbol count, canaries, and the old-to-new rename map. Debugging only; keep it out of shipped artifacts. |
| `--llm <claude\|off>` | Source of decoy text. Default `off`. `claude` reads `ANTHROPIC_API_KEY`; if missing, warns and uses the offline provider. An unrecognized value warns and uses offline. |
| `--keep-public` / `--no-keep-public` | Preserve (default) or allow renaming the public API surface. |
| `--rename-exclude <a,b,...>` | Exclude matching symbol names or `*` wildcard patterns from renaming. |
| `--no-rename` `--no-strings` `--no-controlflow` `--no-misdirection` | Turn off a default-on tier. |
| `--no-flatten` `--no-indirect-dispatch` | Disable control-flow flattening or indirect delegate dispatch within `controlflow`. |
| `--integrity` / `--no-integrity` | Force the integrity tier on / off. |
| `--honeypots` `--poison-decompilers` `--anti-debug` | Turn on a default-off tier. |
| `--anti-debug-decoy` | Enable anti-debug **and** its degrade-to-decoy mode (implies `--anti-debug`): eligible methods divert to inert fake logic while a debugger is attached at load. |
| `--virtualize` / `--no-virtualize` | Enable or disable the method virtualization tier. |
| `--rasp` / `--no-rasp` | Enable or disable runtime self-protection (re-check for debuggers/profilers/tampering during execution; degrade guarded methods to inert fakes). |
| `--no-rasp-native` | Keep RASP but disable its native (Windows/Linux) debugger probes. |
| `--rasp-interval <ms>` | Minimum milliseconds between RASP whole-image re-hashes (default `5000`). |
| `--llm-bloat` / `--no-llm-bloat` | Enable or disable anti-LLM-analysis volume inflation: inject many inert decoy types so the binary is token-expensive to analyze with an LLM. Passive, author's-own-binary only. Amount/cap via config (`features.llmBloat.intensity` / `maxTypes`). |
| `--only <a,b,...>` | Enable only the listed tiers; all others off. |
| `--off <a,b,...>` | Turn off the listed tiers. |

Tier names for `--only`/`--off`: `rename`, `strings`, `controlflow`, `misdirection`, `integrity`,
`polymorphism`, `honeypots`, `poison`, `llmbloat`, `antidebug`, `virtualize`, `rasp`.

## Flag ordering

Flags apply in the order typed; a later `--only`/`--off` overrides an earlier tier flag (for example
`--honeypots --only rename` leaves honeypots off). Unknown tier names in `--only`/`--off` are ignored
without a warning. The resolution precedence overall is **CLI > config file > built-in default**.

## Output

On success the CLI prints the output path, the renamed-symbol count, and any honeypot canary. With
`--map` it also writes the JSON result file.

## Exit codes

- `0`: success (or usage printed when non-empty arguments do not start with `dotnet obfuscate`).
- `1`: an obfuscation error, or no arguments given.
- `2`: bad arguments (unknown option, missing option value, or missing input assembly).

## Related docs

[feature-flags-and-config](feature-flags-and-config.md) · [architecture](architecture.md) · [llm-provider](llm-provider.md)
