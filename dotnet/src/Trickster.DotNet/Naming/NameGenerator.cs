using System.Text;
using Trickster.Core.Entropy;

namespace Trickster.DotNet.Naming;

/// <summary>
/// Produces hostile, hard-to-read identifiers driven by the entropy source. Names are built
/// from a pool of visually confusable Unicode letters (homoglyphs of l / I / o), so distinct
/// identifiers look identical to a human and defeat eyeball mapping. Uniqueness is tracked so
/// no two generated names collide. The IL/CLR accepts these names even though C# would not,
/// which also degrades decompiler output.
/// </summary>
public sealed class NameGenerator
{
    // All are valid identifier letters, visually near-identical in most fonts.
    private static readonly char[] Confusables =
    {
        'l', // l  LATIN SMALL LETTER L
        'I', // I  LATIN CAPITAL LETTER I
        'ı', // ı  LATIN SMALL LETTER DOTLESS I
        'ӏ', // ӏ  CYRILLIC SMALL LETTER PALOCHKA
        'І', // І  CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
        'Ɩ', // Ɩ  LATIN CAPITAL LETTER IOTA
    };

    private readonly EntropySource _entropy;
    private readonly HashSet<string> _used = new(StringComparer.Ordinal);

    public NameGenerator(EntropySource entropy) => _entropy = entropy;

    /// <summary>A fresh unique confusable identifier, 8–16 characters long.</summary>
    public string Next()
    {
        for (int attempt = 0; attempt < 1000; attempt++)
        {
            int len = _entropy.NextInt(8, 17);
            var sb = new StringBuilder(len);
            for (int i = 0; i < len; i++)
                sb.Append(Confusables[_entropy.NextInt(Confusables.Length)]);
            var name = sb.ToString();
            if (_used.Add(name))
                return name;
        }
        throw new InvalidOperationException("Exhausted confusable name space.");
    }
}
