using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Injects a configurable, large number of inert decoy types to inflate the token footprint of
/// the author's own binary when it is decompiled and fed to an LLM for analysis. LLMs have bounded
/// context windows, so a module that decompiles into a large, low-signal body of source degrades
/// LLM-assisted reverse engineering: the analyst's tool overflows its window or spends its budget
/// on filler. This is the LLM-era analogue of <see cref="DecompilerPoisonTransform"/> (which
/// degrades decompilers); this tier degrades LLM analysis by raw volume.
///
/// Defensive scope: this is passive volume inflation of the author's OWN artifact only. It emits no
/// string literals, no readable narrative, and no metadata text, so there is no prompt-injection
/// payload surface and nothing is aimed at a third party's AI agent or service. The decoy types are
/// additive and their methods are type-correct no-ops, so program behavior is unchanged. Higher
/// output-size cost, so this tier is opt-in and bounded by <c>maxTypes</c>.
/// </summary>
public sealed class LlmBloatTransform : DotNetTransform
{
    // A small fixed number of inert methods per decoy type; keeps each type non-trivial without
    // emitting any text or non-inert IL.
    private const int MethodsPerType = 4;

    public override string Name => "llm-bloat";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;
        int count = context.Config.Features.LlmBloat.ResolvedTypeCount;

        for (int i = 0; i < count; i++)
        {
            var type = new TypeDefinition(
                "Trickster.Bloat", gen.Next(),
                TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed,
                module.TypeSystem.Object);
            AddDefaultCtor(module, type);

            for (int m = 0; m < MethodsPerType; m++)
                type.Methods.Add(BuildInertMethod(module, gen.Next()));

            module.Types.Add(type);
        }

        context.Logger.Info($"llm-bloat: injected {count} inert decoy type(s)");
    }

    private static MethodDefinition BuildInertMethod(ModuleDefinition module, string name)
    {
        var method = new MethodDefinition(
            name,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.Int32);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldc_I4_0);  // type-correct no-op: push 0 and return it
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
}
