namespace Trickster.Core;

/// <summary>
/// A single obfuscation pass over a context. Transforms are only ever constructed
/// and run when their feature flag is enabled (see <see cref="FeatureFlags"/>).
/// </summary>
public interface ITransform<in TContext> where TContext : IObfuscationContext
{
    /// <summary>Stable, human-readable name used in logs.</summary>
    string Name { get; }

    void Apply(TContext context);
}
