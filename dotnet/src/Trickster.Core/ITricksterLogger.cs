namespace Trickster.Core;

/// <summary>Minimal logging seam so the pipeline stays host-agnostic.</summary>
public interface ITricksterLogger
{
    void Info(string message);
    void Warn(string message);
}

/// <summary>Writes log lines to the console.</summary>
public sealed class ConsoleLogger : ITricksterLogger
{
    public void Info(string message) => Console.WriteLine($"[trickster] {message}");
    public void Warn(string message) => Console.Error.WriteLine($"[trickster:warn] {message}");
}

/// <summary>Swallows all output; useful in tests.</summary>
public sealed class NullLogger : ITricksterLogger
{
    public static readonly NullLogger Instance = new();
    public void Info(string message) { }
    public void Warn(string message) { }
}
