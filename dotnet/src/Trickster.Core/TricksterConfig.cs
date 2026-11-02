using System.Text.Json;
using System.Text.Json.Serialization;

namespace Trickster.Core;

/// <summary>
/// Root configuration. Deserialized from a JSON config file and/or overlaid by CLI flags.
/// Every tier lives behind a flag in <see cref="Features"/>; a disabled transform is never
/// constructed or run.
/// </summary>
public sealed class TricksterConfig
{
    /// <summary>
    /// Path to a user-supplied secret seed/keyfile. When null the build is
    /// non-deterministic (CSPRNG from OS entropy). When set, builds are reproducible and
    /// security rests on the secrecy of this file, not of the (open-source) algorithm.
    /// </summary>
    [JsonPropertyName("seedFile")]
    public string? SeedFile { get; set; }

    [JsonPropertyName("llm")]
    public LlmConfig Llm { get; set; } = new();

    [JsonPropertyName("features")]
    public FeatureFlags Features { get; set; } = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static TricksterConfig Load(string path)
    {
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<TricksterConfig>(json, JsonOptions)
               ?? throw new InvalidOperationException($"Could not parse config: {path}");
    }

    public static TricksterConfig Default() => new();
}

public sealed class LlmConfig
{
    /// <summary>"off" | "claude". Defaults to offline/templated generation.</summary>
    [JsonPropertyName("provider")]
    public string Provider { get; set; } = "off";
}

/// <summary>
/// One independent flag per tier. Behavior-safe tiers default on; higher-risk / dual-use
/// tiers (honeypots, decompiler poisoning, anti-debug) default off.
/// </summary>
public sealed class FeatureFlags
{
    [JsonPropertyName("rename")]
    public RenameOptions Rename { get; set; } = new();

    [JsonPropertyName("stringEncryption")]
    public ToggleOptions StringEncryption { get; set; } = new() { Enabled = true };

    [JsonPropertyName("controlFlow")]
    public ControlFlowOptions ControlFlow { get; set; } = new();

    [JsonPropertyName("llmMisdirection")]
    public MisdirectionOptions LlmMisdirection { get; set; } = new();

    [JsonPropertyName("integrityChecks")]
    public ToggleOptions IntegrityChecks { get; set; } = new() { Enabled = true };

    [JsonPropertyName("polymorphism")]
    public ToggleOptions Polymorphism { get; set; } = new() { Enabled = true };

    [JsonPropertyName("honeypots")]
    public ToggleOptions Honeypots { get; set; } = new() { Enabled = false };

    [JsonPropertyName("decompilerPoison")]
    public ToggleOptions DecompilerPoison { get; set; } = new() { Enabled = false };

    [JsonPropertyName("antiDebug")]
    public AntiDebugOptions AntiDebug { get; set; } = new() { Enabled = false };

    [JsonPropertyName("virtualization")]
    public ToggleOptions Virtualization { get; set; } = new() { Enabled = false };

    [JsonPropertyName("rasp")]
    public RaspOptions Rasp { get; set; } = new() { Enabled = false };
}

/// <summary>Base for a flag that is simply on/off.</summary>
public class ToggleOptions
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;
}

public sealed class RenameOptions : ToggleOptions
{
    /// <summary>When true, the public API surface is preserved (names not changed).</summary>
    [JsonPropertyName("keepPublic")]
    public bool KeepPublic { get; set; } = true;

    /// <summary>
    /// Symbol names or wildcard patterns (matching simple Name or FullName) to exclude from renaming.
    /// </summary>
    [JsonPropertyName("exclude")]
    public List<string> Exclude { get; set; } = new();
}

public sealed class ControlFlowOptions : ToggleOptions
{
    [JsonPropertyName("opaquePredicates")]
    public bool OpaquePredicates { get; set; } = true;

    [JsonPropertyName("flatten")]
    public bool Flatten { get; set; } = true;

    [JsonPropertyName("indirectDispatch")]
    public bool IndirectDispatch { get; set; } = true;
}

public sealed class AntiDebugOptions : ToggleOptions
{
    /// <summary>
    /// When true, the tier degrades to decoy on detection: a debugger attached at load diverts
    /// eligible methods into an inert decoy routine that returns a type-correct default instead
    /// of running the real body. When false (default) the tier only installs the benign
    /// read-and-discard probe. Opt-in; takes no destructive action and no AV/EDR evasion.
    /// </summary>
    [JsonPropertyName("decoy")]
    public bool Decoy { get; set; } = false;
}

/// <summary>
/// Runtime Application Self-Protection. Opt-in, off by default. Injects a runtime monitor that
/// re-checks for debuggers, profilers, and whole-image tampering during execution (not only at
/// load) and, on detection, degrades eligible methods to inert fake return values. Detection-only:
/// no destructive action, no machine impact, no AV/EDR/sandbox evasion.
/// </summary>
public sealed class RaspOptions : ToggleOptions
{
    /// <summary>Re-sample the managed <c>Debugger.IsAttached</c>/<c>IsLogging</c> flags live.</summary>
    [JsonPropertyName("liveDebuggerCheck")]
    public bool LiveDebuggerCheck { get; set; } = true;

    /// <summary>
    /// Detect native debuggers the managed flag misses (Windows: <c>IsDebuggerPresent</c> /
    /// <c>CheckRemoteDebuggerPresent</c>; Linux: <c>/proc/self/status</c> <c>TracerPid</c>). macOS
    /// is not covered. OS-gated and wrapped in try/catch so it never faults an unsupported host.
    /// </summary>
    [JsonPropertyName("nativeDebuggerCheck")]
    public bool NativeDebuggerCheck { get; set; } = true;

    /// <summary>Detect an attached CLR profiler/hook via the standard profiler environment variables.</summary>
    [JsonPropertyName("profilerCheck")]
    public bool ProfilerCheck { get; set; } = true;

    /// <summary>
    /// Re-verify the whole-image SHA-256 during execution (throttled by <see cref="IntegrityIntervalMs"/>).
    /// Requires the <c>integrity</c> tier; skipped with a build-time warning if it is disabled.
    /// </summary>
    [JsonPropertyName("periodicIntegrityCheck")]
    public bool PeriodicIntegrityCheck { get; set; } = true;

    /// <summary>Minimum milliseconds between whole-image re-hashes (amortizes the cost).</summary>
    [JsonPropertyName("integrityIntervalMs")]
    public int IntegrityIntervalMs { get; set; } = 5000;
}

public sealed class MisdirectionOptions : ToggleOptions
{
    /// <summary>"low" | "medium" | "high": scales how many decoys are injected.</summary>
    [JsonPropertyName("intensity")]
    public string Intensity { get; set; } = "medium";

    public int DecoyTypeCount => Intensity.ToLowerInvariant() switch
    {
        "low" => 2,
        "high" => 12,
        _ => 5,
    };
}
