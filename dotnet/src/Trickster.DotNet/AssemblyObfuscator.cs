using Trickster.Core;
using Trickster.Core.Llm;

namespace Trickster.DotNet;

/// <summary>Outcome of an obfuscation run, surfaced to the CLI/tests.</summary>
public sealed record ObfuscationResult(
    string OutputPath, int RenamedSymbols, IReadOnlyList<string> Canaries,
    IReadOnlyDictionary<string, string> RenameMap, string? Fingerprint = null);

/// <summary>
/// Convenience facade over <see cref="DotNetObfuscationEngine"/> wired with the default codec and
/// tier registry. Kept so existing call sites (CLI, tests) need no change; new call sites that
/// want to inject a codec or a custom registry should use the engine directly.
/// </summary>
public static class AssemblyObfuscator
{
    public static ObfuscationResult Obfuscate(
        string inputPath, string outputPath,
        TricksterConfig config, ILlmProvider llm, ITricksterLogger logger)
        => new DotNetObfuscationEngine().Obfuscate(inputPath, outputPath, config, llm, logger);
}
