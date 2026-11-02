namespace Trickster.Core.Artifacts;

/// <summary>Default in-memory <see cref="IObfuscationArtifacts"/>, keyed by artifact name.</summary>
public sealed class ObfuscationArtifacts : IObfuscationArtifacts
{
    private readonly Dictionary<string, object?> _values = new(StringComparer.Ordinal);

    public void Set<T>(ArtifactKey<T> key, T value) => _values[key.Name] = value;

    public bool TryGet<T>(ArtifactKey<T> key, out T value)
    {
        if (_values.TryGetValue(key.Name, out var raw) && raw is T typed)
        {
            value = typed;
            return true;
        }
        value = default!;
        return false;
    }

    public bool Has(ArtifactKey key) => _values.ContainsKey(key.Name);
}
