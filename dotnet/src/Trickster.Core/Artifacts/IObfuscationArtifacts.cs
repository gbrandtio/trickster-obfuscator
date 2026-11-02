namespace Trickster.Core.Artifacts;

/// <summary>
/// Typed blackboard for values passed between transforms. Replaces ad-hoc mutable fields on
/// the context: a transform publishes what it <c>Produces</c> and reads what it
/// <c>Consumes</c>, so inter-tier handoffs are explicit and the dependency graph is data the
/// <c>TransformChainBuilder</c> can validate.
/// </summary>
public interface IObfuscationArtifacts
{
    void Set<T>(ArtifactKey<T> key, T value);
    bool TryGet<T>(ArtifactKey<T> key, out T value);
    bool Has(ArtifactKey key);
}
