namespace Trickster.Core.Composition;

/// <summary>
/// Assembles a <see cref="TransformChain{TContext}"/> from a registry and config: orders tiers by
/// their <see cref="ITransformModule{TContext}.Order"/> band and validates inter-tier handoffs.
/// <para>
/// Validation rule: for each enabled tier, every artifact it consumes that is produced by some
/// <em>enabled</em> tier must be produced <em>earlier</em> in the order. An enabled producer
/// ordered after its consumer is a bug (the consumer would silently see nothing) and throws a
/// <see cref="CompositionException"/>. A consumed artifact whose only producer is <em>disabled</em>
/// is treated as optional — the consumer degrades gracefully, as before.
/// </para>
/// </summary>
public static class TransformChainBuilder
{
    public static TransformChain<TContext> Build<TContext>(
        ITransformRegistry<TContext> registry, TricksterConfig config)
        where TContext : IObfuscationContext
    {
        // Stable order: Order band, then registration order for ties.
        var ordered = registry.Modules
            .Select((m, i) => (Module: m, Index: i))
            .OrderBy(x => x.Module.Order)
            .ThenBy(x => x.Index)
            .Select(x => x.Module)
            .ToList();

        var enabled = ordered.Where(m => m.IsEnabled(config)).ToList();

        Validate(ordered, enabled, config);

        // Chain of responsibility over all modules; disabled links self-skip at Handle time.
        TransformLink<TContext>? head = null, tail = null;
        foreach (var module in ordered)
        {
            var link = new TransformLink<TContext>(module, config);
            if (head is null) { head = tail = link; }
            else { tail = tail!.SetNext(link); }
        }

        return new TransformChain<TContext>(head, enabled);
    }

    private static void Validate<TContext>(
        IReadOnlyList<ITransformModule<TContext>> ordered,
        IReadOnlyList<ITransformModule<TContext>> enabled,
        TricksterConfig config)
        where TContext : IObfuscationContext
    {
        var enabledSet = new HashSet<ITransformModule<TContext>>(enabled);

        for (int i = 0; i < ordered.Count; i++)
        {
            var consumer = ordered[i];
            if (!enabledSet.Contains(consumer)) continue;

            foreach (var want in consumer.Consumes)
            {
                // Is this artifact produced by any ENABLED tier? If not, it's optional.
                var producers = ordered.Where(m => enabledSet.Contains(m) && m.Produces.Contains(want));
                if (!producers.Any()) continue;

                // It is produced by an enabled tier: that tier must come strictly earlier.
                bool producedEarlier = ordered.Take(i).Any(m => enabledSet.Contains(m) && m.Produces.Contains(want));
                if (!producedEarlier)
                {
                    throw new CompositionException(
                        $"Tier '{consumer.Key}' consumes artifact '{want.Name}', but the enabled tier " +
                        $"that produces it is ordered after '{consumer.Key}'. Fix the tiers' Order so the " +
                        "producer runs first.");
                }
            }
        }
    }
}
