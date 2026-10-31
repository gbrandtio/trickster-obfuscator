using Mono.Cecil;
using Trickster.DotNet.Misdirection;
using Trickster.DotNet.Naming;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Plants a decoy "secrets" type full of fake-but-valuable-looking constants to draw an
/// analyst's attention away from the real mechanism, plus a unique canary constant. The
/// canary is surfaced to the caller so the author can search for it in the wild — if it ever
/// appears downstream, someone shipped against the decoy. All values are inert and fake.
/// </summary>
public sealed class HoneypotTransform : DotNetTransform
{
    public override string Name => "honeypots";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;
        var descrCtor = module.ImportReference(
            typeof(System.ComponentModel.DescriptionAttribute).GetConstructor(new[] { typeof(string) }));

        var type = new TypeDefinition(
            string.Empty, gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var story = CoverStoryCorpus.Pick(context.Entropy, "configuration");
        var attr = new CustomAttribute(descrCtor);
        attr.ConstructorArguments.Add(
            new CustomAttributeArgument(module.TypeSystem.String, story));
        type.CustomAttributes.Add(attr);

        // Valuable-looking but deliberately NOT a real provider key format, so the decoy
        // doesn't trip downstream secret scanners (GitHub push protection, TruffleHog).
        AddConst(module, type, "ApiKey", "tkn_" + Hex(context.Entropy, 24));
        AddConst(module, type, "AesKey", Hex(context.Entropy, 32));
        AddConst(module, type, "SigningSecret", Hex(context.Entropy, 20));

        var canary = "TRICKSTER-CANARY-" + Hex(context.Entropy, 16).ToUpperInvariant();
        AddConst(module, type, "BuildTag", canary);
        context.Canaries.Add(canary);

        module.Types.Add(type);
        context.Logger.Info($"honeypots: planted decoy secrets; canary={canary}");
    }

    private static void AddConst(ModuleDefinition module, TypeDefinition type, string name, string value)
    {
        var field = new FieldDefinition(
            name,
            FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal
                | FieldAttributes.HasDefault,
            module.TypeSystem.String)
        { Constant = value };
        type.Fields.Add(field);
    }

    private static string Hex(Core.Entropy.EntropySource entropy, int bytes)
    {
        var buf = new byte[bytes];
        entropy.NextBytes(buf);
        return Convert.ToHexString(buf).ToLowerInvariant();
    }
}
