using Trickster.Core.Artifacts;
using Trickster.Core.IO;

namespace Trickster.Core.Composition;

/// <summary>
/// Self-describing registration for one obfuscation tier. The module owns its own feature-flag
/// gate (<see cref="IsEnabled"/>/<see cref="SetEnabled"/>) and declares the artifacts it
/// <see cref="Produces"/> and <see cref="Consumes"/>, so the chain builder can order tiers and
/// detect a consumer that would run before its (enabled) producer. Adding a tier is a single new
/// module: the registry, chain builder, and CLI flag handling all discover it by <see cref="Key"/>.
/// </summary>
public interface ITransformModule<TContext> where TContext : IObfuscationContext
{
    /// <summary>Stable flag name, e.g. "rename" or "rasp". Used by config overlays and the CLI.</summary>
    string Key { get; }

    /// <summary>Ordering band; lower runs earlier. Encodes semantic ordering that pure data
    /// dependencies cannot (e.g. sealing passes run last).</summary>
    int Order { get; }

    IReadOnlyList<ArtifactKey> Produces { get; }
    IReadOnlyList<ArtifactKey> Consumes { get; }

    bool IsEnabled(TricksterConfig config);
    void SetEnabled(TricksterConfig config, bool enabled);

    ITransform<TContext> Create();

    /// <summary>Steps run against the output file after the chain completes; empty for most tiers.</summary>
    IReadOnlyList<IPostWriteStep> PostWriteSteps { get; }
}
