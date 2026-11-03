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

    [JsonPropertyName("constants")]
    public ConstantOptions Constants { get; set; } = new() { Enabled = true };

    [JsonPropertyName("resourceEncryption")]
    public ResourceEncryptionOptions ResourceEncryption { get; set; } = new() { Enabled = false };

    [JsonPropertyName("fingerprint")]
    public FingerprintOptions Fingerprint { get; set; } = new() { Enabled = false };

    [JsonPropertyName("controlFlow")]
    public ControlFlowOptions ControlFlow { get; set; } = new();

    [JsonPropertyName("llmMisdirection")]
    public MisdirectionOptions LlmMisdirection { get; set; } = new();

    [JsonPropertyName("integrityChecks")]
    public IntegrityOptions IntegrityChecks { get; set; } = new() { Enabled = true };

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

    [JsonPropertyName("llmBloat")]
    public LlmBloatOptions LlmBloat { get; set; } = new() { Enabled = false };
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

/// <summary>
/// Numeric/constant obfuscation. On by default (behavior-safe, like string encryption). Rewrites
/// integer literals (<c>ldc.i4</c>/<c>ldc.i8</c>) into equivalent inline arithmetic so magic
/// numbers, table sizes and flag masks are not readable static anchors. Runs before string
/// encryption so it never touches that tier's emitted byte-array constants.
/// </summary>
public sealed class ConstantOptions : ToggleOptions
{
    /// <summary>"low" | "medium" | "high": the fraction of integer literals rewritten.</summary>
    [JsonPropertyName("intensity")]
    public string Intensity { get; set; } = "medium";

    /// <summary>Percent chance (0-100) a given literal is rewritten, derived from intensity.</summary>
    public int RewriteChance => (Intensity ?? "medium").ToLowerInvariant() switch
    {
        "low" => 35,
        "high" => 100,
        _ => 70,
    };
}

/// <summary>
/// Embedded-resource encryption. Opt-in, off by default. Encrypts the assembly's embedded resources
/// and redirects the author's own <c>Assembly.GetManifestResourceStream(string)</c> calls through an
/// injected decrypting shim. This raises the bar against static/offline resource extraction; the
/// per-build key ships in the assembly, so it is obfuscation, not a cryptographic boundary.
/// </summary>
public sealed class ResourceEncryptionOptions : ToggleOptions
{
    /// <summary>Resource names (exact or <c>*</c>/<c>?</c> wildcard) to leave in the clear.</summary>
    [JsonPropertyName("exclude")]
    public List<string> Exclude { get; set; } = new();
}

/// <summary>
/// Per-build fingerprint for leak forensics. Opt-in, off by default. Embeds a unique identifier
/// across multiple carriers (an encrypted resource plus an inert constant) so a leaked build traces
/// back to a licensee. The id is surfaced to the author in the run result / map and recoverable with
/// the <c>fingerprint-verify</c> command. Own-binary only; no third-party payload.
/// </summary>
public sealed class FingerprintOptions : ToggleOptions
{
    /// <summary>Licensee/customer identifier recorded in the fingerprint (optional).</summary>
    [JsonPropertyName("customerId")]
    public string CustomerId { get; set; } = string.Empty;
}

/// <summary>
/// Integrity / anti-tamper. On by default. Beyond the load-time module-initializer guard, two opt-in
/// upgrades harden it: <see cref="DistributedChecks"/> scatters additional inline verifier calls so a
/// single NOP cannot disable protection, and <see cref="ProbabilisticResponse"/> degrades eligible
/// methods to inert fake returns on tamper instead of throwing at the check site, surfacing the
/// failure far from where it was detected.
/// </summary>
public sealed class IntegrityOptions : ToggleOptions
{
    /// <summary>
    /// Number of additional random methods to seed with an inline whole-image check. 0 (default)
    /// keeps the legacy single load-time guard only.
    /// </summary>
    [JsonPropertyName("distributedChecks")]
    public int DistributedChecks { get; set; } = 0;

    /// <summary>
    /// When true, a tripped distributed check latches a shared flag and eligible methods divert to
    /// inert fake returns rather than the guard throwing immediately. Off by default.
    /// </summary>
    [JsonPropertyName("probabilisticResponse")]
    public bool ProbabilisticResponse { get; set; } = false;
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
    /// <c>CheckRemoteDebuggerPresent</c>; Linux: <c>/proc/self/status</c> <c>TracerPid</c>; macOS:
    /// <c>sysctl</c> <c>KERN_PROC</c> <c>P_TRACED</c>). OS-gated and wrapped in try/catch so it never
    /// faults an unsupported host.
    /// </summary>
    [JsonPropertyName("nativeDebuggerCheck")]
    public bool NativeDebuggerCheck { get; set; } = true;

    /// <summary>
    /// Detect known reverse-engineering tools running on the host by process name (dnSpy, ILSpy,
    /// dotPeek, x64dbg, Frida, Wireshark, …). Opt-in, off by default (process enumeration can
    /// false-positive on developer/CI machines). Throttled; degrades, never crashes.
    /// </summary>
    [JsonPropertyName("analysisToolCheck")]
    public bool AnalysisToolCheck { get; set; } = false;

    /// <summary>
    /// Detect coarse virtual-machine / sandbox artifacts (e.g. an implausibly small processor count).
    /// Opt-in, off by default (false-positive-prone on legitimate VMs). Degrades, never crashes.
    /// </summary>
    [JsonPropertyName("sandboxCheck")]
    public bool SandboxCheck { get; set; } = false;

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

/// <summary>
/// Anti-LLM-analysis volume inflation. Opt-in, off by default. Injects a large number of inert,
/// additive decoy types so the author's own binary is token-expensive to analyze when decompiled
/// and fed to an LLM. Passive and defensive: emits no text/payload and targets no third-party
/// agent or service. Bounded by <see cref="MaxTypes"/> so output size cannot balloon unboundedly.
/// </summary>
public sealed class LlmBloatOptions : ToggleOptions
{
    /// <summary>"low" | "medium" | "high": scales how many inert decoy types are injected.</summary>
    [JsonPropertyName("intensity")]
    public string Intensity { get; set; } = "medium";

    /// <summary>Hard ceiling on injected decoy types, so output size stays bounded.</summary>
    [JsonPropertyName("maxTypes")]
    public int MaxTypes { get; set; } = 500;

    public int ResolvedTypeCount => Math.Min(MaxTypes, (Intensity ?? "medium").ToLowerInvariant() switch
    {
        "low" => 25,
        "high" => 200,
        _ => 75,
    });
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
