using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Trickster.DotNet.Runtime;

/// <summary>Shared Cecil plumbing used across transforms.</summary>
internal static class CecilExtensions
{
    /// <summary>
    /// Returns the module's &lt;Module&gt; type static constructor (module initializer),
    /// creating an empty one (just `ret`) if it does not yet exist.
    /// </summary>
    public static MethodDefinition GetOrCreateModuleInitializer(this ModuleDefinition module)
    {
        var moduleType = module.GetType("<Module>")
                         ?? module.Types.First(t => t.Name == "<Module>");

        var cctor = moduleType.Methods.FirstOrDefault(m => m.Name == ".cctor");
        if (cctor is not null)
            return cctor;

        cctor = new MethodDefinition(
            ".cctor",
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig
                | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
            module.TypeSystem.Void);
        cctor.Body = new MethodBody(cctor);
        cctor.Body.GetILProcessor().Emit(OpCodes.Ret);
        moduleType.Methods.Add(cctor);
        return cctor;
    }

    /// <summary>Insert a call to <paramref name="target"/> at the very start of the initializer.</summary>
    public static void PrependCall(this MethodDefinition initializer, MethodReference target)
    {
        var il = initializer.Body.GetILProcessor();
        var first = initializer.Body.Instructions[0];
        il.InsertBefore(first, il.Create(OpCodes.Call, target));
    }
}
