using Trickster.Core.Entropy;

namespace Trickster.Core.Llm;

/// <summary>
/// Default <see cref="ILlmProvider"/>: no network, no API key. Assembles decoy names and
/// cover stories from templates driven by the entropy source, so output still varies per
/// build when the entropy source is non-deterministic.
/// </summary>
public sealed class OfflineProvider : ILlmProvider
{
    private readonly EntropySource _entropy;

    public OfflineProvider(EntropySource entropy) => _entropy = entropy;

    public bool IsEnabled => false;

    private static readonly string[] Prefixes =
        { "Buffer", "Cache", "Metrics", "Session", "Telemetry", "Pool", "Channel", "Registry", "Sync", "Batch" };
    private static readonly string[] Roles =
        { "Manager", "Formatter", "Collector", "Scheduler", "Adapter", "Writer", "Resolver", "Dispatcher", "Handler", "Builder" };

    public Task<IReadOnlyList<string>> SuggestDecoyNamesAsync(
        string fakeDomainHint, int count, CancellationToken ct = default)
    {
        var names = new List<string>(count);
        for (int i = 0; i < count; i++)
            names.Add($"{_entropy.Pick(Prefixes)}{_entropy.Pick(Roles)}");
        return Task.FromResult<IReadOnlyList<string>>(names);
    }

    public Task<string> GenerateCoverStoryAsync(string fakeDomainHint, CancellationToken ct = default)
    {
        var story = $"Internal {fakeDomainHint} helper. Buffers batched work items and flushes " +
                    "them on a timer; not part of the public contract.";
        return Task.FromResult(MisdirectionGuard.Require(story));
    }
}
