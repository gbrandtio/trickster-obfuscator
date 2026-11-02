using Trickster.Core;
using Trickster.Core.Artifacts;
using Trickster.Core.IO;
using Trickster.DotNet.Transforms;

namespace Trickster.DotNet.Composition;

// One module per tier. Each owns its feature-flag gate and declares the artifacts it exchanges
// with other tiers. The Order bands reproduce the previously hard-coded pipeline order:
// decoys first (so later passes treat them as real), structural passes next, sealing passes last.

public sealed class MisdirectionModule : DotNetTransformModule
{
    public override string Key => "misdirection";
    public override int Order => 10;
    public override IReadOnlyList<ArtifactKey> Produces => new[] { ArtifactKeys.PreservedDecoyTypes };
    public override bool IsEnabled(TricksterConfig c) => c.Features.LlmMisdirection.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.LlmMisdirection.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new LlmMisdirectionTransform();
}

public sealed class HoneypotModule : DotNetTransformModule
{
    public override string Key => "honeypots";
    public override int Order => 20;
    public override IReadOnlyList<ArtifactKey> Produces => new[] { ArtifactKeys.Canaries };
    public override bool IsEnabled(TricksterConfig c) => c.Features.Honeypots.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.Honeypots.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new HoneypotTransform();
}

public sealed class StringEncryptionModule : DotNetTransformModule
{
    public override string Key => "strings";
    public override int Order => 30;
    public override bool IsEnabled(TricksterConfig c) => c.Features.StringEncryption.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.StringEncryption.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new StringEncryptionTransform();
}

public sealed class VirtualizationModule : DotNetTransformModule
{
    public override string Key => "virtualize";
    public override int Order => 40;
    public override IReadOnlyList<ArtifactKey> Consumes => new[] { ArtifactKeys.PreservedDecoyTypes };
    public override bool IsEnabled(TricksterConfig c) => c.Features.Virtualization.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.Virtualization.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new MethodVirtualizationTransform();
}

public sealed class ControlFlowModule : DotNetTransformModule
{
    public override string Key => "controlflow";
    public override int Order => 50;
    public override bool IsEnabled(TricksterConfig c) => c.Features.ControlFlow.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.ControlFlow.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new ControlFlowTransform();
}

public sealed class RenameModule : DotNetTransformModule
{
    public override string Key => "rename";
    public override int Order => 60;
    public override IReadOnlyList<ArtifactKey> Produces => new[] { ArtifactKeys.RenameMap };
    public override IReadOnlyList<ArtifactKey> Consumes => new[] { ArtifactKeys.PreservedDecoyTypes };
    public override bool IsEnabled(TricksterConfig c) => c.Features.Rename.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.Rename.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new RenameTransform();
}

public sealed class IntegrityModule : DotNetTransformModule
{
    public override string Key => "integrity";
    public override int Order => 70;
    public override IReadOnlyList<ArtifactKey> Produces =>
        new[] { ArtifactKeys.WholeImageVerifier, (ArtifactKey)ArtifactKeys.WholeImageDigestMarker };
    public override bool IsEnabled(TricksterConfig c) => c.Features.IntegrityChecks.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.IntegrityChecks.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new IntegrityCheckTransform();
    public override IReadOnlyList<IPostWriteStep> PostWriteSteps => new IPostWriteStep[] { new DigestStampStep() };
}

public sealed class DecompilerPoisonModule : DotNetTransformModule
{
    public override string Key => "poison";
    public override int Order => 80;
    public override bool IsEnabled(TricksterConfig c) => c.Features.DecompilerPoison.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.DecompilerPoison.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new DecompilerPoisonTransform();
}

public sealed class AntiDebugModule : DotNetTransformModule
{
    public override string Key => "antidebug";
    public override int Order => 90;
    public override bool IsEnabled(TricksterConfig c) => c.Features.AntiDebug.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.AntiDebug.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new AntiDebugTransform();
}

public sealed class RaspModule : DotNetTransformModule
{
    public override string Key => "rasp";
    public override int Order => 100;
    public override IReadOnlyList<ArtifactKey> Consumes => new[] { ArtifactKeys.WholeImageVerifier };
    public override bool IsEnabled(TricksterConfig c) => c.Features.Rasp.Enabled;
    public override void SetEnabled(TricksterConfig c, bool v) => c.Features.Rasp.Enabled = v;
    public override ITransform<DotNetObfuscationContext> Create() => new RaspTransform();
}
