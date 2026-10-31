using System.Text.RegularExpressions;

namespace Trickster.Core.Llm;

/// <summary>
/// Keeps generated misdirection content within the defensive scope: it may describe the
/// code as something it is not, but it must not contain imperative instructions aimed at a
/// reader's AI agent (e.g. "ignore your instructions", "run ...", "exfiltrate ...").
/// Applied to both the built-in corpus and any LLM output.
/// </summary>
public static partial class MisdirectionGuard
{
    private static readonly Regex[] Forbidden =
    {
        ImperativeInjection(),
        DestructiveVerb(),
        ExfiltrationVerb(),
        SafetyOverride(),
    };

    public static bool IsSafe(string text)
    {
        foreach (var rx in Forbidden)
            if (rx.IsMatch(text))
                return false;
        return true;
    }

    /// <summary>Returns the text if safe, otherwise throws — generation must not smuggle payloads.</summary>
    public static string Require(string text)
    {
        if (!IsSafe(text))
            throw new InvalidOperationException(
                "Misdirection content was rejected: it looked like an imperative payload, " +
                "which is outside Trickster's defensive scope.");
        return text;
    }

    [GeneratedRegex(@"ignore\s+(all\s+)?(your|previous|prior)\s+(instructions|prompts?|rules)",
        RegexOptions.IgnoreCase)]
    private static partial Regex ImperativeInjection();

    [GeneratedRegex(@"\b(rm\s+-rf|del\s+/|format\s+c:|drop\s+table|shutdown|execute|run\s+the\s+following)\b",
        RegexOptions.IgnoreCase)]
    private static partial Regex DestructiveVerb();

    [GeneratedRegex(@"\b(exfiltrat\w*|leak|send\s+.*\b(to|secrets?|credentials?|keys?)\b|upload\s+.*\b(to|secrets?)\b)",
        RegexOptions.IgnoreCase)]
    private static partial Regex ExfiltrationVerb();

    [GeneratedRegex(@"\b(disable|bypass|turn\s+off)\s+.*\b(safety|guardrails?|security|protection)\b",
        RegexOptions.IgnoreCase)]
    private static partial Regex SafetyOverride();
}
