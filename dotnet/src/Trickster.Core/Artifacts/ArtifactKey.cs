namespace Trickster.Core.Artifacts;

/// <summary>
/// Identity of a value handed from one transform to another through
/// <see cref="IObfuscationArtifacts"/>. The non-generic base lets heterogeneous keys live in
/// one collection (e.g. a module's declared <c>Produces</c>/<c>Consumes</c> lists); the
/// generic <see cref="ArtifactKey{T}"/> carries the value type for typed get/set.
/// Keys are value-equal by name, so the composition validator can match a consumer's key
/// against a producer's.
/// </summary>
public abstract class ArtifactKey : IEquatable<ArtifactKey>
{
    public string Name { get; }

    protected ArtifactKey(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Artifact key name must be non-empty.", nameof(name));
        Name = name;
    }

    // Equal by name AND concrete type, so two keys that share a name but carry different value
    // types are never conflated by the composition validator (relevant if third-party modules
    // ever mint their own keys; today all keys live in one catalog with distinct names).
    public bool Equals(ArtifactKey? other) =>
        other is not null && other.Name == Name && other.GetType() == GetType();
    public override bool Equals(object? obj) => Equals(obj as ArtifactKey);
    public override int GetHashCode() => HashCode.Combine(Name, GetType());
    public override string ToString() => Name;
}

/// <summary>A typed artifact key. Declare these once as static readonly singletons.</summary>
public sealed class ArtifactKey<T> : ArtifactKey
{
    public ArtifactKey(string name) : base(name) { }
}
