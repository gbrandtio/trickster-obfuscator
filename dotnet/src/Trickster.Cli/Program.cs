using System.Text.Json;
using Trickster.Core;
using Trickster.Core.Entropy;
using Trickster.Core.Llm;
using Trickster.DotNet;
using Trickster.DotNet.Composition;
using Trickster.Llm.Claude;

if (args.Length >= 2 && args[0] == "dotnet" && args[1] == "fingerprint-verify")
{
    if (args.Length < 3) { Console.Error.WriteLine("Usage: trickster dotnet fingerprint-verify <assembly>"); return 2; }
    try
    {
        var id = Trickster.DotNet.Transforms.FingerprintReader.Read(args[2]);
        if (id is null) { Console.WriteLine("No Trickster fingerprint found."); return 1; }
        Console.WriteLine($"Fingerprint: {id}");
        return 0;
    }
    catch (Exception ex) { Console.Error.WriteLine($"error: {ex.Message}"); return 1; }
}

if (args.Length < 2 || args[0] != "dotnet" || args[1] != "obfuscate")
{
    PrintUsage();
    return args.Length == 0 ? 1 : 0;
}

var rest = args.Skip(2).ToArray();
string? input = null, output = null, configPath = null, seedFile = null, mapPath = null, llm = null;
var overrides = new List<Action<TricksterConfig>>();

try
{
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
            case "--rename-exclude":
            {
                var items = Next(rest, ref i)
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                overrides.Add(c => c.Features.Rename.Exclude.AddRange(items));
                break;
            }
            case "--no-rename": overrides.Add(c => c.Features.Rename.Enabled = false); break;
            case "--no-strings": overrides.Add(c => c.Features.StringEncryption.Enabled = false); break;
            case "--no-constants": overrides.Add(c => c.Features.Constants.Enabled = false); break;
            case "--constants-intensity":
                { var v = Next(rest, ref i); overrides.Add(c => c.Features.Constants.Intensity = v); break; }
            case "--encrypt-resources": overrides.Add(c => c.Features.ResourceEncryption.Enabled = true); break;
            case "--fingerprint": overrides.Add(c => c.Features.Fingerprint.Enabled = true); break;
            case "--fingerprint-id":
                { var id = Next(rest, ref i); overrides.Add(c => { c.Features.Fingerprint.Enabled = true; c.Features.Fingerprint.CustomerId = id; }); break; }
            case "--integrity-distributed":
            {
                var v = Next(rest, ref i);
                if (!int.TryParse(v, out var n) || n < 0) throw new ArgumentException($"Invalid --integrity-distributed value: {v}");
                overrides.Add(c => { c.Features.IntegrityChecks.Enabled = true; c.Features.IntegrityChecks.DistributedChecks = n; });
                break;
            }
            case "--integrity-probabilistic":
                overrides.Add(c => { c.Features.IntegrityChecks.Enabled = true; c.Features.IntegrityChecks.ProbabilisticResponse = true; });
                break;
            case "--rasp-analysis": overrides.Add(c => { c.Features.Rasp.Enabled = true; c.Features.Rasp.AnalysisToolCheck = true; }); break;
            case "--rasp-sandbox": overrides.Add(c => { c.Features.Rasp.Enabled = true; c.Features.Rasp.SandboxCheck = true; }); break;
            case "--no-controlflow": overrides.Add(c => c.Features.ControlFlow.Enabled = false); break;
            case "--no-flatten": overrides.Add(c => c.Features.ControlFlow.Flatten = false); break;
            case "--no-indirect-dispatch": overrides.Add(c => c.Features.ControlFlow.IndirectDispatch = false); break;
            case "--no-misdirection": overrides.Add(c => c.Features.LlmMisdirection.Enabled = false); break;
            case "--integrity": overrides.Add(c => c.Features.IntegrityChecks.Enabled = true); break;
            case "--no-integrity": overrides.Add(c => c.Features.IntegrityChecks.Enabled = false); break;
            case "--honeypots": overrides.Add(c => c.Features.Honeypots.Enabled = true); break;
            case "--poison-decompilers": overrides.Add(c => c.Features.DecompilerPoison.Enabled = true); break;
            case "--anti-debug": overrides.Add(c => c.Features.AntiDebug.Enabled = true); break;
            case "--anti-debug-decoy":
                overrides.Add(c => { c.Features.AntiDebug.Enabled = true; c.Features.AntiDebug.Decoy = true; });
                break;
            case "--virtualize": overrides.Add(c => c.Features.Virtualization.Enabled = true); break;
            case "--no-virtualize": overrides.Add(c => c.Features.Virtualization.Enabled = false); break;
            case "--llm-bloat": overrides.Add(c => c.Features.LlmBloat.Enabled = true); break;
            case "--no-llm-bloat": overrides.Add(c => c.Features.LlmBloat.Enabled = false); break;
            case "--rasp": overrides.Add(c => c.Features.Rasp.Enabled = true); break;
            case "--no-rasp": overrides.Add(c => c.Features.Rasp.Enabled = false); break;
            case "--no-rasp-native": overrides.Add(c => c.Features.Rasp.NativeDebuggerCheck = false); break;
            case "--rasp-interval":
            {
                var v = Next(rest, ref i);
                if (!int.TryParse(v, out var ms) || ms < 0)
                    throw new ArgumentException($"Invalid --rasp-interval value: {v}");
                overrides.Add(c => c.Features.Rasp.IntegrityIntervalMs = ms);
                break;
            }
            case "--only": overrides.Add(OnlyOverlay(Next(rest, ref i))); break;
            case "--off": overrides.Add(OffOverlay(Next(rest, ref i))); break;
            default:
                if (a.StartsWith('-')) { Console.Error.WriteLine($"Unknown option: {a}"); return 2; }
                input ??= a;
                break;
        }
    }
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    return 2;
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
    if (result.Fingerprint is not null)
        Console.WriteLine($"Fingerprint (recover with 'fingerprint-verify'): {result.Fingerprint}");

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

static bool IsEnabled(TricksterConfig c, string flag)
{
    // "polymorphism" is not a tier (it selects the entropy source), so it is handled directly;
    // every real tier is discovered from the registry by its Key.
    if (flag == "polymorphism") return c.Features.Polymorphism.Enabled;
    var module = DotNetTransformRegistry.Default.Modules.FirstOrDefault(m => m.Key == flag);
    return module is not null && module.IsEnabled(c);
}

static void ApplyMask(TricksterConfig c, Func<string, bool> want)
{
    foreach (var module in DotNetTransformRegistry.Default.Modules)
        module.SetEnabled(c, want(module.Key));
    c.Features.Polymorphism.Enabled = want("polymorphism");
}

static void PrintUsage()
{
    Console.WriteLine(
@"Trickster Obfuscator (.NET)

Usage:
  trickster dotnet obfuscate <input.dll> -o <output.dll> [options]
  trickster dotnet fingerprint-verify <assembly>   Recover an embedded build fingerprint

Options:
  -o, --output <path>        Output assembly path (defaults to overwriting input)
  --config <path>            JSON config file
  --seed-file <path>         Secret seed for a reproducible build (else non-deterministic)
  --map <path>               Write the rename map + result as JSON (debugging only)
  --llm <claude|off>         Provider for decoy generation (default off; uses ANTHROPIC_API_KEY)
  --keep-public              Preserve the public API surface (default on)
  --no-keep-public           Also rename the public API surface
  --rename-exclude <a,b,...> Exclude matching symbols or wildcard patterns from renaming
  --no-rename --no-strings --no-controlflow --no-flatten --no-indirect-dispatch --no-misdirection
  --no-constants             Disable integer-literal obfuscation (on by default)
  --constants-intensity <low|medium|high>
  --encrypt-resources        Encrypt embedded resources + redirect GetManifestResourceStream calls
  --fingerprint              Embed a per-build leak-tracing fingerprint
  --fingerprint-id <id>      Embed a fingerprint tagged with this licensee/customer id
  --integrity-distributed <n>  Scatter n extra inline integrity checks across methods
  --integrity-probabilistic    Degrade methods to inert fakes on tamper instead of throwing
  --rasp-analysis            RASP: also detect known analysis tools (dnSpy, Frida, …)
  --rasp-sandbox             RASP: also detect coarse VM/sandbox artifacts
  --integrity --no-integrity --honeypots --poison-decompilers --anti-debug
  --anti-debug-decoy         Anti-debug + degrade-to-decoy: eligible methods divert to inert
                             decoy logic while a debugger is attached (implies --anti-debug)
  --virtualize               Compile eligible integer/boolean methods into custom VM bytecode
  --no-virtualize            Disable method virtualization
  --llm-bloat                Inject many inert decoy types so the binary is token-expensive to
                             analyze with an LLM (passive, author's-own-binary only; see docs).
                             Amount/cap via config (features.llmBloat.intensity / maxTypes)
  --no-llm-bloat             Disable anti-LLM-analysis volume inflation
  --rasp                     Runtime self-protection: re-check for debuggers/profilers/tampering
                             during execution and degrade guarded methods to inert fakes
  --no-rasp                  Disable runtime self-protection
  --no-rasp-native           Keep RASP but disable its native (Windows/Linux) debugger probes
  --rasp-interval <ms>       Min milliseconds between RASP whole-image re-hashes (default 5000)
  --only <a,b,...>           Enable only these tiers
  --off  <a,b,...>           Disable these tiers
  Tier names: rename, strings, constants, resources, fingerprint, controlflow, misdirection,
              integrity, polymorphism, honeypots, poison, llmbloat, antidebug, virtualize, rasp");
}
