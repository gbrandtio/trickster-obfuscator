using Mono.Cecil;
using Trickster.Core;
using Trickster.Core.Llm;
using Trickster.DotNet.Polymorphism;
using Trickster.DotNet.Transforms;

namespace Trickster.DotNet;

/// <summary>Outcome of an obfuscation run, surfaced to the CLI/tests.</summary>
public sealed record ObfuscationResult(
    string OutputPath, int RenamedSymbols, IReadOnlyList<string> Canaries,
    IReadOnlyDictionary<string, string> RenameMap);

/// <summary>
/// Entry point for the .NET engine: loads an assembly, runs the enabled transforms in order,
/// and writes the result. Only transforms whose feature flag is enabled are constructed.
/// </summary>
public static class AssemblyObfuscator
{
    public static ObfuscationResult Obfuscate(
        string inputPath, string outputPath,
        TricksterConfig config, ILlmProvider llm, ITricksterLogger logger)
    {
        var resolver = new DefaultAssemblyResolver();
        var dir = Path.GetDirectoryName(Path.GetFullPath(inputPath));
        if (!string.IsNullOrEmpty(dir)) resolver.AddSearchDirectory(dir);

        var readParams = new ReaderParameters
        {
            ReadingMode = ReadingMode.Immediate,
            InMemory = true,
            AssemblyResolver = resolver,
        };

        using var assembly = AssemblyDefinition.ReadAssembly(inputPath, readParams);

        var entropy = MutationEngine.CreateEntropy(config);
        logger.Info(entropy.IsDeterministic
            ? "entropy: deterministic (reproducible build)"
            : "entropy: non-deterministic (CSPRNG)");

        var context = new DotNetObfuscationContext(assembly, config, entropy, llm, logger);
        var pipeline = new ObfuscationPipeline<DotNetObfuscationContext>(BuildTransforms(config));
        pipeline.Run(context);

        assembly.Write(outputPath);
        logger.Info($"wrote {outputPath}");

        return new ObfuscationResult(
            outputPath, context.RenameMap.Count, context.Canaries, context.RenameMap);
    }

    private static IReadOnlyList<ITransform<DotNetObfuscationContext>> BuildTransforms(
        TricksterConfig config)
    {
        var f = config.Features;
        var list = new List<ITransform<DotNetObfuscationContext>>();

        // Order: decoys first (so later passes treat them as real), structural passes next,
        // then sealing passes (integrity/poison/anti-debug) last.
        if (f.LlmMisdirection.Enabled) list.Add(new LlmMisdirectionTransform());
        if (f.Honeypots.Enabled)       list.Add(new HoneypotTransform());
        if (f.StringEncryption.Enabled) list.Add(new StringEncryptionTransform());
        if (f.ControlFlow.Enabled)     list.Add(new ControlFlowTransform());
        if (f.Rename.Enabled)          list.Add(new RenameTransform());
        if (f.IntegrityChecks.Enabled) list.Add(new IntegrityCheckTransform());
        if (f.DecompilerPoison.Enabled) list.Add(new DecompilerPoisonTransform());
        if (f.AntiDebug.Enabled)       list.Add(new AntiDebugTransform());

        return list;
    }
}
