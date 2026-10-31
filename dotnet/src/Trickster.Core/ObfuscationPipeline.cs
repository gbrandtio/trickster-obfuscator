namespace Trickster.Core;

/// <summary>Runs an ordered list of enabled transforms over a context.</summary>
public sealed class ObfuscationPipeline<TContext> where TContext : IObfuscationContext
{
    private readonly IReadOnlyList<ITransform<TContext>> _transforms;

    public ObfuscationPipeline(IReadOnlyList<ITransform<TContext>> transforms)
        => _transforms = transforms;

    public void Run(TContext context)
    {
        foreach (var transform in _transforms)
        {
            context.Logger.Info($"pass: {transform.Name}");
            transform.Apply(context);
        }
    }
}
