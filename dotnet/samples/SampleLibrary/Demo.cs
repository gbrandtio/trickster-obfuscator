namespace SampleLibrary;

/// <summary>
/// A small library exercising the features the obfuscator must preserve: public API,
/// private helpers, string literals, branches, loops, and exception handling.
/// </summary>
public static class Demo
{
    public static string Run(int n)
    {
        var parts = new List<string>();
        for (int i = 1; i <= n; i++)
            parts.Add($"{i}:{Classify(i)}");

        string joined = string.Join(", ", parts);
        return $"Demo result for {n} => [{joined}] sum={SumTo(n)} label={SafeLabel(n)}";
    }

    public static int Add(int a, int b) => a + b;

    /// <summary>Reads an embedded resource; exercises resource-encryption's runtime shim.</summary>
    public static string ReadPayload()
    {
        var asm = typeof(Demo).Assembly;
        using var stream = asm.GetManifestResourceStream("SampleLibrary.payload.txt");
        if (stream is null) return "<missing>";
        using var reader = new System.IO.StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string Classify(int value)
    {
        if (value % 2 == 0) return "even";
        return "odd";
    }

    private static int SumTo(int n)
    {
        int total = 0;
        for (int i = 1; i <= n; i++) total += i;
        return total;
    }

    private static string SafeLabel(int n)
    {
        try
        {
            if (n < 0) throw new ArgumentOutOfRangeException(nameof(n), "negative");
            return n == 0 ? "zero" : "positive";
        }
        catch (ArgumentOutOfRangeException)
        {
            return "invalid";
        }
    }
}
