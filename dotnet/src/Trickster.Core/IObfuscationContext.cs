using Trickster.Core.Artifacts;
using Trickster.Core.Entropy;
using Trickster.Core.Llm;

namespace Trickster.Core;

/// <summary>
/// Shared surface every language engine exposes to its transforms. Language-specific
/// engines (e.g. the .NET/Cecil engine) derive from this and add their own model
/// (such as the loaded assembly).
/// </summary>
public interface IObfuscationContext
{
    TricksterConfig Config { get; }
    EntropySource Entropy { get; }
    ILlmProvider Llm { get; }
    ITricksterLogger Logger { get; }

    /// <summary>Typed blackboard for values passed between transforms.</summary>
    IObfuscationArtifacts Artifacts { get; }
}
