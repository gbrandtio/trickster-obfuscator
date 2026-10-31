using Mono.Cecil;
using Mono.Cecil.Cil;
using Trickster.DotNet.Naming;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Adds inert decoy members whose names are valid CLR metadata but not valid C#
/// identifiers (they mimic compiler-generated names). Common decompilers render these with
/// awkward escaping or give up, so the analyst's tools — not just comments — mislead.
/// Members are unreferenced and do nothing, and output is validated by the round-trip load
/// test. Higher runtime-validity risk, so this tier is opt-in.
/// </summary>
public sealed class DecompilerPoisonTransform : DotNetTransform
{
    // Shapes that resemble real compiler artifacts and confuse decompilers, but are
    // metadata-legal and safe for the CLR to load.
    private static readonly string[] HostileNames =
    {
        "<>c__DisplayTrap", "<Poison>b__0", "<>9__Decoy", "get_<trap>k__", "<Finally>d__7",
    };

    public override string Name => "decompiler-poison";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;

        var type = new TypeDefinition(
            string.Empty, "<>c__" + gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        foreach (var hostile in HostileNames)
        {
            var m = new MethodDefinition(
                hostile,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig,
                module.TypeSystem.Void);
            m.Body.GetILProcessor().Emit(OpCodes.Ret);
            type.Methods.Add(m);
        }

        module.Types.Add(type);
        context.Logger.Info($"decompiler-poison: added {HostileNames.Length} hostile-named decoy(s)");
    }
}
