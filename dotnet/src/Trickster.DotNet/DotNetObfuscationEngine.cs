using Trickster.Core;
using Trickster.Core.Composition;
using Trickster.Core.Llm;
using Trickster.DotNet.Composition;
using Trickster.DotNet.IO;
using Trickster.DotNet.Polymorphism;

namespace Trickster.DotNet;

/// <summary>
/// Coordinates one obfuscation run: read -> build context -> run the validated transform chain ->
/// write -> run each enabled tier's post-write steps -> collect output artifacts. An instance type
/// with injected collaborators (codec, registry) so it is testable and extensible; see
/// <see cref="AssemblyObfuscator"/> for the default-wired convenience facade.
/// </summary>
public sealed class DotNetObfuscationEngine
{
    private readonly IAssemblyCodec _codec;
    private readonly ITransformRegistry<DotNetObfuscationContext> _registry;

    public DotNetObfuscationEngine(
        IAssemblyCodec? codec = null,
        ITransformRegistry<DotNetObfuscationContext>? registry = null)
    {
        _codec = codec ?? new CecilAssemblyCodec();
        _registry = registry ?? DotNetTransformRegistry.Default;
    }

    public ObfuscationResult Obfuscate(
        string inputPath, string outputPath,
        TricksterConfig config, ILlmProvider llm, ITricksterLogger logger)
    {
        using var assembly = _codec.Read(inputPath);

        var entropy = MutationEngine.CreateEntropy(config);
        logger.Info(entropy.IsDeterministic
            ? "entropy: deterministic (reproducible build)"
            : "entropy: non-deterministic (CSPRNG)");

        var context = new DotNetObfuscationContext(assembly, config, entropy, llm, logger);
        var chain = TransformChainBuilder.Build(_registry, config);
        chain.Run(context);

        _codec.Write(assembly, outputPath);

        foreach (var module in chain.EnabledModules)
            foreach (var step in module.PostWriteSteps)
                step.Apply(outputPath, context.Artifacts);

        logger.Info($"wrote {outputPath}");

        var map = context.Artifacts.TryGet(ArtifactKeys.RenameMap, out var m)
            ? m : new Dictionary<string, string>();
        var canaries = context.Artifacts.TryGet(ArtifactKeys.Canaries, out var c)
            ? c : new List<string>();
        var fingerprint = context.Artifacts.TryGet(ArtifactKeys.Fingerprint, out var fp) ? fp : null;

        return new ObfuscationResult(outputPath, map.Count, canaries, map, fingerprint);
    }
}
