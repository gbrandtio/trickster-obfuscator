using Trickster.Core;
using Xunit;

namespace Trickster.DotNet.Tests;

public class BehaviorPreservationTests
{
    private static readonly string Expected = SampleLibrary.Demo.Run(5);

    [Fact]
    public void AllTiersOn_PreservesBehavior()
    {
        var path = ObfuscationHarness.Obfuscate(ObfuscationHarness.AllTiersOn(), "all");
        Assert.Equal(Expected, ObfuscationHarness.InvokeRun(path, 5));
    }

    public static IEnumerable<object[]> SingleTierConfigs()
    {
        yield return new object[] { "rename", Mutate(c => Only(c, "rename")) };
        yield return new object[] { "strings", Mutate(c => Only(c, "strings")) };
        yield return new object[] { "controlflow", Mutate(c => Only(c, "controlflow")) };
        yield return new object[] { "misdirection", Mutate(c => Only(c, "misdirection")) };
        yield return new object[] { "integrity", Mutate(c => Only(c, "integrity")) };
        yield return new object[] { "honeypots", Mutate(c => Only(c, "honeypots")) };
        yield return new object[] { "poison", Mutate(c => Only(c, "poison")) };
        yield return new object[] { "antidebug", Mutate(c => Only(c, "antidebug")) };
        yield return new object[] { "antidebug-decoy", Mutate(c =>
        {
            Only(c, "antidebug");
            c.Features.AntiDebug.Decoy = true;
        }) };
        yield return new object[] { "virtualize", Mutate(c => Only(c, "virtualize")) };
        yield return new object[] { "rasp", Mutate(c => Only(c, "rasp")) };
        // RASP + integrity so the periodic whole-image re-check is wired and exercised.
        yield return new object[] { "rasp-integrity", Mutate(c =>
        {
            Only(c, "rasp");
            c.Features.IntegrityChecks.Enabled = true;
        }) };
    }

    [Theory]
    [MemberData(nameof(SingleTierConfigs))]
    public void EachTier_PreservesBehavior(string tag, TricksterConfig config)
    {
        var path = ObfuscationHarness.Obfuscate(config, tag);
        Assert.Equal(Expected, ObfuscationHarness.InvokeRun(path, 5));
    }

    [Fact]
    public void ControlFlow_PreservesExceptionHandlingPath()
    {
        // SafeLabel(n) throws for negative n and catches it internally; the opaque-predicate
        // guard the control-flow pass inserts at method entry must not disturb that
        // surrounding try/catch region.
        var expected = SampleLibrary.Demo.Run(-1);
        var path = ObfuscationHarness.Obfuscate(Mutate(c => Only(c, "controlflow")), "controlflow-exn");
        Assert.Equal(expected, ObfuscationHarness.InvokeRun(path, -1));
    }

    private static TricksterConfig Mutate(Action<TricksterConfig> f)
    {
        var c = TricksterConfig.Default();
        f(c);
        return c;
    }

    // Turn everything off, then enable only the named tier (polymorphism left as-is).
    private static void Only(TricksterConfig c, string tier)
    {
        var f = c.Features;
        f.Rename.Enabled = f.StringEncryption.Enabled = f.ControlFlow.Enabled =
            f.LlmMisdirection.Enabled = f.IntegrityChecks.Enabled =
            f.Honeypots.Enabled = f.DecompilerPoison.Enabled = f.AntiDebug.Enabled =
            f.Virtualization.Enabled = false;
        switch (tier)
        {
            case "rename": f.Rename.Enabled = true; break;
            case "strings": f.StringEncryption.Enabled = true; break;
            case "controlflow": f.ControlFlow.Enabled = true; break;
            case "misdirection": f.LlmMisdirection.Enabled = true; break;
            case "integrity": f.IntegrityChecks.Enabled = true; break;
            case "honeypots": f.Honeypots.Enabled = true; break;
            case "poison": f.DecompilerPoison.Enabled = true; break;
            case "antidebug": f.AntiDebug.Enabled = true; break;
            case "virtualize": f.Virtualization.Enabled = true; break;
            case "rasp": f.Rasp.Enabled = true; break;
        }
    }
}
