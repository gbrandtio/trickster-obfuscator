using Trickster.Core;
using Trickster.Core.Artifacts;
using Trickster.Core.Composition;
using Trickster.Core.IO;

namespace Trickster.DotNet.Composition;

/// <summary>Base for .NET tier modules: empty produces/consumes/post-write by default.</summary>
public abstract class DotNetTransformModule : ITransformModule<DotNetObfuscationContext>
{
    public abstract string Key { get; }
    public abstract int Order { get; }
    public virtual IReadOnlyList<ArtifactKey> Produces => Array.Empty<ArtifactKey>();
    public virtual IReadOnlyList<ArtifactKey> Consumes => Array.Empty<ArtifactKey>();
    public abstract bool IsEnabled(TricksterConfig config);
    public abstract void SetEnabled(TricksterConfig config, bool enabled);
    public abstract ITransform<DotNetObfuscationContext> Create();
    public virtual IReadOnlyList<IPostWriteStep> PostWriteSteps => Array.Empty<IPostWriteStep>();
}
