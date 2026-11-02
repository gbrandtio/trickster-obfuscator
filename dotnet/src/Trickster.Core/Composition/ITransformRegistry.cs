namespace Trickster.Core.Composition;

/// <summary>
/// The catalog of available tiers for an engine. An explicit (non-reflection) list keeps the
/// security-sensitive default-off tiers auditable and AOT/trim-friendly.
/// </summary>
public interface ITransformRegistry<TContext> where TContext : IObfuscationContext
{
    IReadOnlyList<ITransformModule<TContext>> Modules { get; }
}
