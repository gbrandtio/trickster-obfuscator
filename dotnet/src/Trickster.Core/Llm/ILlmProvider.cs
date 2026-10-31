namespace Trickster.Core.Llm;

/// <summary>
/// Optional generation seam used by the misdirection tier to produce context-aware decoy
/// names and false-narrative cover stories. Always has an offline fallback so the
/// deterministic tiers work with no API key.
/// </summary>
public interface ILlmProvider
{
    bool IsEnabled { get; }

    /// <summary>Plausible-but-wrong identifier names fitting the given fake domain.</summary>
    Task<IReadOnlyList<string>> SuggestDecoyNamesAsync(
        string fakeDomainHint, int count, CancellationToken ct = default);

    /// <summary>
    /// A short, coherent false narrative describing the code as something it is not.
    /// Output is passed through <see cref="MisdirectionGuard"/> before use.
    /// </summary>
    Task<string> GenerateCoverStoryAsync(string fakeDomainHint, CancellationToken ct = default);
}
