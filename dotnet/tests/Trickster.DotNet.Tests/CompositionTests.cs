using Trickster.Core;
using Trickster.Core.Artifacts;
using Trickster.Core.Composition;
using Trickster.Core.IO;
using Trickster.DotNet;
using Trickster.DotNet.Composition;
using Xunit;

namespace Trickster.DotNet.Tests;

public class CompositionTests
{
    private static readonly ArtifactKey<int> Handoff = new("TestHandoff");

    /// <summary>A no-op tier used to probe the builder's ordering validation.</summary>
    private sealed class FakeModule : DotNetTransformModule
    {
        private readonly bool _enabled;
        public FakeModule(string key, int order, bool enabled,
            ArtifactKey[]? produces = null, ArtifactKey[]? consumes = null)
        {
            Key = key; Order = order; _enabled = enabled;
            Produces = produces ?? System.Array.Empty<ArtifactKey>();
            Consumes = consumes ?? System.Array.Empty<ArtifactKey>();
        }
        public override string Key { get; }
        public override int Order { get; }
        public override IReadOnlyList<ArtifactKey> Produces { get; }
        public override IReadOnlyList<ArtifactKey> Consumes { get; }
        public override bool IsEnabled(TricksterConfig c) => _enabled;
        public override void SetEnabled(TricksterConfig c, bool v) { }
        public override ITransform<DotNetObfuscationContext> Create() => new NoopTransform();
    }

    private sealed class NoopTransform : DotNetTransform
    {
        public override string Name => "noop";
        public override void Apply(DotNetObfuscationContext context) { }
    }

    private sealed class FakeRegistry : ITransformRegistry<DotNetObfuscationContext>
    {
        public FakeRegistry(params ITransformModule<DotNetObfuscationContext>[] modules) => Modules = modules;
        public IReadOnlyList<ITransformModule<DotNetObfuscationContext>> Modules { get; }
    }

    [Fact]
    public void Build_Throws_WhenEnabledConsumerOrderedBeforeEnabledProducer()
    {
        var consumer = new FakeModule("consumer", order: 1, enabled: true, consumes: new ArtifactKey[] { Handoff });
        var producer = new FakeModule("producer", order: 2, enabled: true, produces: new ArtifactKey[] { Handoff });
        var registry = new FakeRegistry(consumer, producer);

        var ex = Assert.Throws<CompositionException>(
            () => TransformChainBuilder.Build(registry, TricksterConfig.Default()));
        Assert.Contains("consumer", ex.Message);
        Assert.Contains("TestHandoff", ex.Message);
    }

    [Fact]
    public void Build_Succeeds_WhenProducerOrderedBeforeConsumer()
    {
        var producer = new FakeModule("producer", order: 1, enabled: true, produces: new ArtifactKey[] { Handoff });
        var consumer = new FakeModule("consumer", order: 2, enabled: true, consumes: new ArtifactKey[] { Handoff });
        var registry = new FakeRegistry(producer, consumer);

        var chain = TransformChainBuilder.Build(registry, TricksterConfig.Default());
        Assert.Equal(2, chain.EnabledModules.Count);
    }

    [Fact]
    public void Build_Succeeds_WhenProducerDisabled_ConsumerDegradesGracefully()
    {
        // Mirrors rasp-without-integrity: the producer is simply off, so the consume is optional.
        var producer = new FakeModule("producer", order: 2, enabled: false, produces: new ArtifactKey[] { Handoff });
        var consumer = new FakeModule("consumer", order: 1, enabled: true, consumes: new ArtifactKey[] { Handoff });
        var registry = new FakeRegistry(producer, consumer);

        var chain = TransformChainBuilder.Build(registry, TricksterConfig.Default());
        Assert.Single(chain.EnabledModules);
    }

    [Fact]
    public void DefaultRegistry_BuildsWithoutCompositionError()
    {
        // Every enable combination the CLI can select must assemble; default config is the baseline.
        var chain = TransformChainBuilder.Build(DotNetTransformRegistry.Default, TricksterConfig.Default());
        Assert.NotEmpty(chain.EnabledModules);
    }
}
