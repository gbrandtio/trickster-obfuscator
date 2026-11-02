using Trickster.Core.Composition;

namespace Trickster.DotNet.Composition;

/// <summary>
/// The .NET engine's tier catalog. An explicit list (not reflection) keeps the dual-use
/// default-off tiers auditable in one place and stays AOT/trim-friendly. To add a tier: write its
/// module and add one line here.
/// </summary>
public sealed class DotNetTransformRegistry : ITransformRegistry<DotNetObfuscationContext>
{
    public static readonly DotNetTransformRegistry Default = new();

    public IReadOnlyList<ITransformModule<DotNetObfuscationContext>> Modules { get; } =
        new ITransformModule<DotNetObfuscationContext>[]
        {
            new MisdirectionModule(),
            new HoneypotModule(),
            new StringEncryptionModule(),
            new VirtualizationModule(),
            new ControlFlowModule(),
            new RenameModule(),
            new IntegrityModule(),
            new DecompilerPoisonModule(),
            new LlmBloatModule(),
            new AntiDebugModule(),
            new RaspModule(),
        };
}
