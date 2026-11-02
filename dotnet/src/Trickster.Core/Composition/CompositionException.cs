namespace Trickster.Core.Composition;

/// <summary>
/// Thrown when the transform chain cannot be assembled — currently when an enabled tier is
/// ordered before an enabled tier that produces an artifact it consumes (a silent no-op in the
/// old design). Fails loudly at composition time instead of producing a broken build.
/// </summary>
public sealed class CompositionException : Exception
{
    public CompositionException(string message) : base(message) { }
}
