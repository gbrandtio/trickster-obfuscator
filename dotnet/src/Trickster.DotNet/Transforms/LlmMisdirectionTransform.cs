using Mono.Cecil;
using Mono.Cecil.Cil;
using Trickster.Core.Llm;
using Trickster.DotNet.Misdirection;
using Trickster.DotNet.Naming;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Injects decoy types carrying a coherent *false* narrative. The readable misdirection
/// lives in [Description] attributes (stored in metadata, so neither string-encryption nor
/// renaming removes it) while the decoy method bodies carry cover-story string literals that
/// the string-encryption pass later hides — making the decoys look like protected logic.
/// Narrative text (corpus or LLM) is validated by <see cref="MisdirectionGuard"/>.
/// </summary>
public sealed class LlmMisdirectionTransform : DotNetTransform
{
    public override string Name => "llm-misdirection";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;
        int count = context.Config.Features.LlmMisdirection.DecoyTypeCount;

        var descrCtor = module.ImportReference(
            typeof(System.ComponentModel.DescriptionAttribute).GetConstructor(new[] { typeof(string) }));

        for (int i = 0; i < count; i++)
        {
            var domain = context.Entropy.Pick(CoverStoryCorpus.Domains);
            var story = BuildStory(context, domain);

            var type = new TypeDefinition(
                "Trickster.Decoys", gen.Next(),
                TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed,
                module.TypeSystem.Object);
            AddDescription(type, descrCtor, story);
            AddDefaultCtor(module, type);

            int methodCount = context.Entropy.NextInt(1, 4);
            for (int m = 0; m < methodCount; m++)
                type.Methods.Add(BuildDecoyMethod(module, gen.Next(), descrCtor, domain, story));

            module.Types.Add(type);
        }

        context.Logger.Info($"llm-misdirection: injected {count} decoy type(s)");
    }

    private static string BuildStory(DotNetObfuscationContext ctx, string domain)
    {
        if (ctx.Llm.IsEnabled)
        {
            try
            {
                var text = ctx.Llm.GenerateCoverStoryAsync(domain).GetAwaiter().GetResult();
                return MisdirectionGuard.Require(text);
            }
            catch (Exception ex)
            {
                // A provider failure (network, rate limit, timeout) must not abort the whole
                // obfuscation — fall back to the offline corpus.
                ctx.Logger.Warn($"llm cover-story generation failed, using offline corpus: {ex.Message}");
            }
        }
        return CoverStoryCorpus.Pick(ctx.Entropy, domain);
    }

    private static MethodDefinition BuildDecoyMethod(
        ModuleDefinition module, string name, MethodReference descrCtor, string domain, string story)
    {
        var method = new MethodDefinition(
            name,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.String);
        AddDescription(method, descrCtor, story);

        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, $"[{domain}] {story}");  // hidden later by string-encryption
        il.Emit(OpCodes.Ret);
        return method;
    }

    private static void AddDefaultCtor(ModuleDefinition module, TypeDefinition type)
    {
        var objCtor = module.ImportReference(typeof(object).GetConstructor(Type.EmptyTypes));
        var ctor = new MethodDefinition(
            ".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName
                | MethodAttributes.RTSpecialName,
            module.TypeSystem.Void);
        var il = ctor.Body.GetILProcessor();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Call, objCtor);
        il.Emit(OpCodes.Ret);
        type.Methods.Add(ctor);
    }

    private static void AddDescription(
        ICustomAttributeProvider target, MethodReference descrCtor, string text)
    {
        var attr = new CustomAttribute(descrCtor);
        attr.ConstructorArguments.Add(
            new CustomAttributeArgument(descrCtor.Module.TypeSystem.String, text));
        target.CustomAttributes.Add(attr);
    }
}
