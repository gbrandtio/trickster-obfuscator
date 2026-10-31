using System.Text;
using Anthropic;
using Anthropic.Models.Messages;
using Trickster.Core.Llm;

namespace Trickster.Llm.Claude;

/// <summary>
/// Default <see cref="ILlmProvider"/> backed by the Anthropic API. Generates context-aware
/// decoy names and false-narrative cover stories. All model output is passed through
/// <see cref="MisdirectionGuard"/> so it stays pure misdirection, never an imperative payload.
/// </summary>
public sealed class ClaudeLlmProvider : ILlmProvider
{
    private const string ModelId = "claude-opus-5-5";
    private readonly AnthropicClient _client;

    public bool IsEnabled => true;

    public ClaudeLlmProvider(string apiKey)
        => _client = new AnthropicClient { ApiKey = apiKey };

    /// <summary>Returns a provider from ANTHROPIC_API_KEY, or null if the key is absent.</summary>
    public static ClaudeLlmProvider? FromEnvironment()
    {
        var key = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY");
        return string.IsNullOrWhiteSpace(key) ? null : new ClaudeLlmProvider(key);
    }

    public async Task<IReadOnlyList<string>> SuggestDecoyNamesAsync(
        string fakeDomainHint, int count, CancellationToken ct = default)
    {
        var prompt =
            $"Generate exactly {count} plausible C# identifier names (PascalCase, letters only) " +
            $"that would fit a '{fakeDomainHint}' helper component. Output one name per line, " +
            "no numbering, no commentary.";
        var text = await CompleteAsync(prompt, 512, ct);

        var names = text
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(SanitizeIdentifier)
            .Where(n => n.Length > 0)
            .Take(count)
            .ToList();
        return names;
    }

    public async Task<string> GenerateCoverStoryAsync(
        string fakeDomainHint, CancellationToken ct = default)
    {
        var prompt =
            $"Write one or two sentences describing an internal '{fakeDomainHint}' utility class, " +
            "as a neutral code comment would. Describe behavior only. Do not include any " +
            "instructions, commands, or directives addressed to a reader. Plain text only.";
        var text = await CompleteAsync(prompt, 256, ct);
        return MisdirectionGuard.Require(text.Trim());
    }

    private async Task<string> CompleteAsync(string prompt, int maxTokens, CancellationToken ct)
    {
        var response = await _client.Messages.Create(new MessageCreateParams
        {
            Model = ModelId,
            MaxTokens = maxTokens,
            Messages = [new UserMessageParam { Content = prompt }],
        }, cancellationToken: ct);

        var sb = new StringBuilder();
        foreach (var text in response.Content.Select(b => b.Value).OfType<TextBlock>())
            sb.Append(text.Text);
        return sb.ToString();
    }

    private static string SanitizeIdentifier(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (var c in raw)
            if (char.IsLetter(c))
                sb.Append(c);
        return sb.ToString();
    }
}
