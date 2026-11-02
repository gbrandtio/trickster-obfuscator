using Mono.Cecil;
using Trickster.Core;
using Trickster.Core.Entropy;
using Trickster.Core.Llm;
using Trickster.DotNet.Naming;

namespace Trickster.DotNet;

/// <summary>
/// The .NET engine's context: everything a transform needs to rewrite a loaded assembly.
/// </summary>
public sealed class DotNetObfuscationContext : IObfuscationContext
{
    public TricksterConfig Config { get; }
    public EntropySource Entropy { get; }
    public ILlmProvider Llm { get; }
    public ITricksterLogger Logger { get; }

    public AssemblyDefinition Assembly { get; }
    public ModuleDefinition Module => Assembly.MainModule;

    /// <summary>Original-name -> obfuscated-name, recorded by the rename pass.</summary>
    public Dictionary<string, string> RenameMap { get; } = new(StringComparer.Ordinal);

    /// <summary>Canary identifiers emitted into the output, surfaced back to the caller.</summary>
    public List<string> Canaries { get; } = new();

    /// <summary>
    /// Decoy types injected with domain-plausible names by the misdirection pass, preserved by
    /// the rename pass so their readable names survive alongside their [Description] stories.
    /// </summary>
    public HashSet<TypeDefinition> PreservedDecoyTypes { get; } = new();

    /// <summary>
    /// Unique 32-byte placeholder marker emitted by the integrity pass into the assembly image.
    /// After the assembly is written to disk, <see cref="AssemblyObfuscator"/> replaces this
    /// marker with the SHA-256 digest of the whole image (with the marker bytes zeroed).
    /// </summary>
    public byte[]? WholeImageDigestMarker { get; set; }

    /// <summary>
    /// The injected <c>static bool</c> whole-image verification method emitted by the integrity
    /// pass (returns <c>true</c> when the on-disk image is intact or cannot be checked). The RASP
    /// pass reuses it for its periodic re-check; null when the integrity tier is disabled.
    /// </summary>
    public MethodDefinition? WholeImageVerifyMethod { get; set; }

    /// <summary>
    /// One name generator shared by every transform, so generated identifiers are unique
    /// across the whole module. Transforms must use this rather than constructing their own,
    /// otherwise two independently-generated names could collide and produce duplicate types.
    /// </summary>
    public NameGenerator Names { get; }

    public DotNetObfuscationContext(
        AssemblyDefinition assembly,
        TricksterConfig config,
        EntropySource entropy,
        ILlmProvider llm,
        ITricksterLogger logger)
    {
        Assembly = assembly;
        Config = config;
        Entropy = entropy;
        Llm = llm;
        Logger = logger;
        Names = new NameGenerator(entropy);
    }
}

/// <summary>Convenience base type for the .NET transforms.</summary>
public abstract class DotNetTransform : ITransform<DotNetObfuscationContext>
{
    public abstract string Name { get; }
    public abstract void Apply(DotNetObfuscationContext context);
}
