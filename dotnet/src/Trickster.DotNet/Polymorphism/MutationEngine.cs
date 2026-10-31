using Trickster.Core;
using Trickster.Core.Entropy;

namespace Trickster.DotNet.Polymorphism;

/// <summary>
/// Chooses the entropy source that drives every transform, which is how polymorphism is
/// realized: when enabled, each build draws different structural choices (non-deterministic
/// by default, or reproducible from a secret seed file). When the polymorphism flag is off,
/// a fixed canonical seed is used so output is stable and comparable.
/// </summary>
public static class MutationEngine
{
    // Arbitrary fixed constant used only when polymorphism is disabled.
    private static readonly byte[] CanonicalSeed =
        { 0x54, 0x72, 0x69, 0x63, 0x6B, 0x73, 0x74, 0x65, 0x72, 0x2D, 0x76, 0x31 };

    public static EntropySource CreateEntropy(TricksterConfig config)
    {
        // A supplied secret seed always wins: it is never silently ignored.
        if (config.SeedFile is { Length: > 0 } seed)
            return EntropySource.FromSeedFile(seed);

        // No seed: canonical fixed seed when polymorphism is off (stable builds),
        // otherwise a fresh CSPRNG per build.
        return config.Features.Polymorphism.Enabled
            ? EntropySource.CreateNonDeterministic()
            : EntropySource.FromSeedBytes(CanonicalSeed);
    }
}
