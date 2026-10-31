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
