using Mono.Cecil;
using Mono.Cecil.Cil;
using Trickster.Core.Llm;
using Trickster.DotNet.Misdirection;
using Trickster.DotNet.Naming;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Injects decoy types carrying a coherent *false* narrative. Decoy type and method names are
/// obtained via <see cref="ILlmProvider.SuggestDecoyNamesAsync"/> (preserving readable,
/// domain-plausible identifiers), while the readable narrative lives in [Description]
/// attributes (stored in metadata) and the decoy method bodies carry cover-story string
/// literals that the string-encryption pass later hides. Narrative text (corpus or LLM) is
/// validated by <see cref="MisdirectionGuard"/>.
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

        var usedTypeNames = new HashSet<string>(
            module.Types.Select(t => t.Name), StringComparer.Ordinal);

        for (int i = 0; i < count; i++)
        {
            var domain = context.Entropy.Pick(CoverStoryCorpus.Domains);
            var story = BuildStory(context, domain);
            int methodCount = context.Entropy.NextInt(1, 4);

            var suggested = SuggestNames(context, domain, 1 + methodCount);
            var typeName = AllocateUniqueName(suggested, 0, usedTypeNames, gen);

            var type = new TypeDefinition(
                "Trickster.Decoys", typeName,
                TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed,
                module.TypeSystem.Object);
            AddDescription(type, descrCtor, story);
            AddDefaultCtor(module, type);

            var usedMethodNames = new HashSet<string>(StringComparer.Ordinal);
            for (int m = 0; m < methodCount; m++)
            {
                var methodName = AllocateUniqueName(suggested, 1 + m, usedMethodNames, gen);
                type.Methods.Add(BuildDecoyMethod(module, methodName, descrCtor, domain, story));
            }

            module.Types.Add(type);
            context.PreservedDecoyTypes.Add(type);
        }

        context.Logger.Info($"llm-misdirection: injected {count} decoy type(s)");
    }

    private static IReadOnlyList<string> SuggestNames(
        DotNetObfuscationContext ctx, string domain, int count)
    {
        if (ctx.Llm.IsEnabled)
        {
            try
            {
                var names = ctx.Llm.SuggestDecoyNamesAsync(domain, count).GetAwaiter().GetResult();
                if (names is { Count: > 0 })
                    return names;
            }
            catch (Exception ex)
            {
                ctx.Logger.Warn($"llm decoy-name generation failed, using offline provider: {ex.Message}");
            }
        }
        return new OfflineProvider(ctx.Entropy)
            .SuggestDecoyNamesAsync(domain, count).GetAwaiter().GetResult();
    }

    private static string AllocateUniqueName(
        IReadOnlyList<string> candidates, int index, HashSet<string> used, NameGenerator fallback)
    {
        if (index < candidates.Count && !string.IsNullOrWhiteSpace(candidates[index]))
        {
            var baseName = candidates[index];
            if (used.Add(baseName))
                return baseName;
            for (int suffix = 2; suffix < 1000; suffix++)
            {
                var numbered = $"{baseName}{suffix}";
                if (used.Add(numbered))
                    return numbered;
            }
        }
        var name = fallback.Next();
        used.Add(name);
        return name;
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
                // obfuscation; fall back to the offline corpus.
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
