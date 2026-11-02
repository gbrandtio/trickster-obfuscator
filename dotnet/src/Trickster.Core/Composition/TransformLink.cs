namespace Trickster.Core.Composition;

/// <summary>
/// One handler in the chain of responsibility. Each link is a tier that decides for itself,
/// from its own feature flag, whether to run, then forwards the context to the next link. This
/// replaces the hard-coded "if (flag) list.Add(...)" ladder: enabling/disabling a tier is a
/// property on its module, and the chain is uniform.
/// </summary>
public sealed class TransformLink<TContext> where TContext : IObfuscationContext
{
    private readonly ITransformModule<TContext> _module;
    private readonly ITransform<TContext> _transform;
    private readonly TricksterConfig _config;
    private TransformLink<TContext>? _next;

    public TransformLink(ITransformModule<TContext> module, TricksterConfig config)
    {
        _module = module;
        _config = config;
        _transform = module.Create();
    }

    /// <summary>Link <paramref name="next"/> after this one; returns it for fluent chaining.</summary>
    public TransformLink<TContext> SetNext(TransformLink<TContext> next)
    {
        _next = next;
        return next;
    }

    public void Handle(TContext context)
    {
        if (_module.IsEnabled(_config))
        {
            context.Logger.Info($"pass: {_transform.Name}");
            _transform.Apply(context);
        }
        _next?.Handle(context);
    }
}
