namespace Trickster.Core.Composition;

/// <summary>
/// An assembled, validated chain of tiers. <see cref="Run"/> drives the chain of responsibility;
/// <see cref="EnabledModules"/> is the enabled tiers in execution order (used by the engine to
/// run post-write steps and collect output artifacts).
/// </summary>
public sealed class TransformChain<TContext> where TContext : IObfuscationContext
{
    private readonly TransformLink<TContext>? _head;

    public IReadOnlyList<ITransformModule<TContext>> EnabledModules { get; }

    internal TransformChain(
        TransformLink<TContext>? head, IReadOnlyList<ITransformModule<TContext>> enabledModules)
    {
        _head = head;
        EnabledModules = enabledModules;
    }

    public void Run(TContext context) => _head?.Handle(context);
}
