using System.Text.Json;
using Trickster.Core;
using Trickster.Core.Entropy;
using Trickster.Core.Llm;
using Trickster.DotNet;
using Trickster.Llm.Claude;

if (args.Length < 2 || args[0] != "dotnet" || args[1] != "obfuscate")
{
    PrintUsage();
    return args.Length == 0 ? 1 : 0;
}

var rest = args.Skip(2).ToArray();
string? input = null, output = null, configPath = null, seedFile = null, mapPath = null, llm = null;
var overrides = new List<Action<TricksterConfig>>();

for (int i = 0; i < rest.Length; i++)
{
    var a = rest[i];
    switch (a)
    {
        case "-o" or "--output": output = Next(rest, ref i); break;
        case "--config": configPath = Next(rest, ref i); break;
        case "--seed-file": seedFile = Next(rest, ref i); break;
        case "--map": mapPath = Next(rest, ref i); break;
        case "--llm": llm = Next(rest, ref i); break;
        case "--keep-public": overrides.Add(c => c.Features.Rename.KeepPublic = true); break;
        case "--no-keep-public": overrides.Add(c => c.Features.Rename.KeepPublic = false); break;
        case "--no-rename": overrides.Add(c => c.Features.Rename.Enabled = false); break;
        case "--no-strings": overrides.Add(c => c.Features.StringEncryption.Enabled = false); break;
        case "--no-controlflow": overrides.Add(c => c.Features.ControlFlow.Enabled = false); break;
        case "--no-misdirection": overrides.Add(c => c.Features.LlmMisdirection.Enabled = false); break;
        case "--integrity": overrides.Add(c => c.Features.IntegrityChecks.Enabled = true); break;
        case "--no-integrity": overrides.Add(c => c.Features.IntegrityChecks.Enabled = false); break;
        case "--honeypots": overrides.Add(c => c.Features.Honeypots.Enabled = true); break;
        case "--poison-decompilers": overrides.Add(c => c.Features.DecompilerPoison.Enabled = true); break;
        case "--anti-debug": overrides.Add(c => c.Features.AntiDebug.Enabled = true); break;
        case "--anti-debug-decoy":
            overrides.Add(c => { c.Features.AntiDebug.Enabled = true; c.Features.AntiDebug.Decoy = true; });
            break;
        case "--only": overrides.Add(OnlyOverlay(Next(rest, ref i))); break;
        case "--off": overrides.Add(OffOverlay(Next(rest, ref i))); break;
        default:
            if (a.StartsWith('-')) { Console.Error.WriteLine($"Unknown option: {a}"); return 2; }
            input ??= a;
            break;
    }
}

if (input is null) { Console.Error.WriteLine("Missing input assembly."); return 2; }
output ??= input;

var config = configPath is not null ? TricksterConfig.Load(configPath) : TricksterConfig.Default();
if (seedFile is not null) config.SeedFile = seedFile;
if (llm is not null) config.Llm.Provider = llm;
foreach (var o in overrides) o(config);

var logger = new ConsoleLogger();
ILlmProvider provider = ResolveProvider(config, logger);

try
{
    var result = AssemblyObfuscator.Obfuscate(input, output, config, provider, logger);
    Console.WriteLine($"Obfuscated -> {result.OutputPath}");
    Console.WriteLine($"Renamed symbols: {result.RenamedSymbols}");
    foreach (var canary in result.Canaries)
        Console.WriteLine($"Canary (search for this in the wild): {canary}");

    if (mapPath is not null)
    {
        // Rename map is written only for local debugging; keep it out of shipped artifacts.
        File.WriteAllText(mapPath,
            JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Wrote map -> {mapPath}");
    }
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

static string Next(string[] a, ref int i)
{
    if (i + 1 >= a.Length) throw new ArgumentException($"Missing value after {a[i]}");
    return a[++i];
}

static ILlmProvider ResolveProvider(TricksterConfig config, ITricksterLogger logger)
{
    var name = config.Llm.Provider;
    if (string.Equals(name, "claude", StringComparison.OrdinalIgnoreCase))
    {
        var claude = ClaudeLlmProvider.FromEnvironment();
        if (claude is not null) return claude;
        logger.Warn("llm=claude requested but ANTHROPIC_API_KEY is not set; using offline provider");
    }
    else if (!string.Equals(name, "off", StringComparison.OrdinalIgnoreCase))
    {
        logger.Warn($"unknown llm provider '{name}'; using offline provider");
    }
    return new OfflineProvider(EntropySource.CreateNonDeterministic());
}

static Action<TricksterConfig> OnlyOverlay(string csv)
{
    var set = csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Select(s => s.ToLowerInvariant()).ToHashSet();
    return c => ApplyMask(c, flag => set.Contains(flag));
}

static Action<TricksterConfig> OffOverlay(string csv)
{
    var set = csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Select(s => s.ToLowerInvariant()).ToHashSet();
    return c => ApplyMask(c, flag => !set.Contains(flag) && IsEnabled(c, flag));
}

static bool IsEnabled(TricksterConfig c, string flag) => flag switch
{
    "rename" => c.Features.Rename.Enabled,
    "strings" => c.Features.StringEncryption.Enabled,
    "controlflow" => c.Features.ControlFlow.Enabled,
    "misdirection" => c.Features.LlmMisdirection.Enabled,
    "integrity" => c.Features.IntegrityChecks.Enabled,
    "polymorphism" => c.Features.Polymorphism.Enabled,
    "honeypots" => c.Features.Honeypots.Enabled,
    "poison" => c.Features.DecompilerPoison.Enabled,
    "antidebug" => c.Features.AntiDebug.Enabled,
    _ => false,
};

static void ApplyMask(TricksterConfig c, Func<string, bool> want)
{
    c.Features.Rename.Enabled = want("rename");
    c.Features.StringEncryption.Enabled = want("strings");
    c.Features.ControlFlow.Enabled = want("controlflow");
    c.Features.LlmMisdirection.Enabled = want("misdirection");
    c.Features.IntegrityChecks.Enabled = want("integrity");
    c.Features.Polymorphism.Enabled = want("polymorphism");
    c.Features.Honeypots.Enabled = want("honeypots");
    c.Features.DecompilerPoison.Enabled = want("poison");
    c.Features.AntiDebug.Enabled = want("antidebug");
}

static void PrintUsage()
{
    Console.WriteLine(
@"Trickster Obfuscator (.NET)

Usage:
  trickster dotnet obfuscate <input.dll> -o <output.dll> [options]

Options:
  -o, --output <path>     Output assembly path (defaults to overwriting input)
  --config <path>         JSON config file
  --seed-file <path>      Secret seed for a reproducible build (else non-deterministic)
  --map <path>            Write the rename map + result as JSON (debugging only)
  --llm <claude|off>      Provider for decoy generation (default off; uses ANTHROPIC_API_KEY)
  --keep-public           Preserve the public API surface (default on)
  --no-keep-public        Also rename the public API surface
  --no-rename --no-strings --no-controlflow --no-misdirection
  --integrity --no-integrity --honeypots --poison-decompilers --anti-debug
  --anti-debug-decoy      Anti-debug + degrade-to-decoy: eligible methods divert to inert
                          decoy logic while a debugger is attached (implies --anti-debug)
  --only <a,b,...>        Enable only these tiers
  --off  <a,b,...>        Disable these tiers
  Tier names: rename, strings, controlflow, misdirection, integrity,
              polymorphism, honeypots, poison, antidebug");
}
