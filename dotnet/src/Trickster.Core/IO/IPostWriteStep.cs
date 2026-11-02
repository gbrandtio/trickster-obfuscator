using Trickster.Core.Artifacts;

namespace Trickster.Core.IO;

/// <summary>
/// A step run against the written output file after the transform chain completes. Lets a tier
/// finish work that can only happen once bytes are on disk (e.g. stamping a whole-image hash)
/// without the engine needing to know that tier's internals. The owning module supplies it via
/// <c>ITransformModule.PostWriteSteps</c>.
/// </summary>
public interface IPostWriteStep
{
    void Apply(string outputPath, IObfuscationArtifacts artifacts);
}
