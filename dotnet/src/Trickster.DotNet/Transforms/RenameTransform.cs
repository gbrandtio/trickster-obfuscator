using Mono.Cecil;
using Trickster.DotNet.Naming;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Conservative symbol renaming. Renames private/internal types and members to hostile
/// confusable names, driven by the entropy source. Preserves the public API surface by
/// default, and skips anything whose renaming could break runtime behavior: constructors,
/// property/event accessors, virtual/abstract/override/interface members, P/Invoke, and
/// interfaces themselves.
/// </summary>
public sealed class RenameTransform : DotNetTransform
{
    public override string Name => "rename";

    public override void Apply(DotNetObfuscationContext context)
    {
        bool keepPublic = context.Config.Features.Rename.KeepPublic;
        var gen = context.Names;
        int types = 0, methods = 0, fields = 0, parameters = 0;

        foreach (var type in context.Module.GetTypes())
        {
            if (type.Name == "<Module>" || type.IsInterface) continue;

            foreach (var method in type.Methods)
            {
                if (!CanRenameMethod(method, keepPublic)) continue;
                Record(context, $"M:{method.FullName}", out var newName, gen);
                method.Name = newName;
                methods++;
                foreach (var p in method.Parameters)
                {
                    p.Name = gen.Next();
                    parameters++;
                }
            }

            foreach (var field in type.Fields)
            {
                if (!CanRenameField(field, keepPublic)) continue;
                Record(context, $"F:{field.FullName}", out var newName, gen);
                field.Name = newName;
                fields++;
            }

            if (CanRenameType(type, keepPublic))
            {
                Record(context, $"T:{type.FullName}", out var newName, gen);
                type.Name = newName;
                if (!type.IsNested) type.Namespace = string.Empty;
                types++;
            }
        }

        context.Logger.Info(
            $"rename: {types} type(s), {methods} method(s), {fields} field(s), {parameters} param(s)");
    }

    private static void Record(
        DotNetObfuscationContext ctx, string key, out string newName, NameGenerator gen)
    {
        newName = gen.Next();
        ctx.RenameMap[key] = newName;
    }

    private static bool CanRenameType(TypeDefinition t, bool keepPublic)
    {
        if (t.Name == "<Module>") return false;
        if (keepPublic && (t.IsPublic || t.IsNestedPublic || t.IsNestedFamily
                           || t.IsNestedFamilyOrAssembly)) return false;
        return true;
    }

    private static bool CanRenameMethod(MethodDefinition m, bool keepPublic)
    {
        if (m.IsConstructor || m.IsRuntimeSpecialName) return false;
        if (m.IsGetter || m.IsSetter || m.IsAddOn || m.IsRemoveOn || m.IsFire) return false;
        if (m.IsVirtual || m.IsAbstract || m.HasOverrides) return false;
        if (m.HasPInvokeInfo) return false;
        if (keepPublic && (m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly)) return false;
        return true;
    }

    private static bool CanRenameField(FieldDefinition f, bool keepPublic)
    {
        if (f.IsRuntimeSpecialName || f.IsSpecialName) return false;
        if (keepPublic && (f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly)) return false;
        return true;
    }
}
