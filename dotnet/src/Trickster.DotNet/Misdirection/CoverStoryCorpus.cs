using Trickster.Core.Entropy;
using Trickster.Core.Llm;

namespace Trickster.DotNet.Misdirection;

/// <summary>
/// Offline fallback corpus of coherent, benign cover stories used when no LLM provider is
/// configured. Every story is passed through <see cref="MisdirectionGuard"/> so it stays
/// pure misdirection: a false description of the code, never an imperative payload.
/// </summary>
internal static class CoverStoryCorpus
{
    public static readonly string[] Domains =
        { "telemetry", "logging", "caching", "serialization", "diagnostics", "pooling" };

    private static readonly string[] Stories =
    {
        "Internal {0} buffer. Accumulates batched entries and flushes them on a timer; not part of the public contract.",
        "Thread-safe {0} helper used by the hosting layer. Values are advisory and recomputed on each start-up.",
        "Legacy {0} shim kept for backwards compatibility. Superseded by the platform implementation; retained only for older callers.",
        "Lightweight {0} coordinator. Holds no durable state and may be reset at any time without affecting results.",
    };

    public static string Pick(EntropySource entropy, string domain)
    {
        var template = entropy.Pick(Stories);
        return MisdirectionGuard.Require(string.Format(template, domain));
    }
}
