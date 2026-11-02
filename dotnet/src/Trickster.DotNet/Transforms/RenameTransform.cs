using System.Text.RegularExpressions;
using Mono.Cecil;
using Trickster.DotNet.Naming;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Conservative symbol renaming. Renames private/internal types and members to hostile
/// confusable names, driven by the entropy source. Preserves the public API surface by
/// default, honors the configured <c>exclude</c> skip-list and <c>[Obfuscation]</c> attributes,
/// preserves decoy types emitted by the misdirection pass, and skips anything whose renaming
/// could break runtime behavior: constructors, property/event accessors,
/// virtual/abstract/override/interface members, P/Invoke, and interfaces themselves.
/// </summary>
public sealed class RenameTransform : DotNetTransform
{
    public override string Name => "rename";

    public override void Apply(DotNetObfuscationContext context)
    {
        bool keepPublic = context.Config.Features.Rename.KeepPublic;
        var excludes = CompilePatterns(context.Config.Features.Rename.Exclude);
        var gen = context.Names;
        int types = 0, methods = 0, fields = 0, parameters = 0;

        foreach (var type in context.Module.GetTypes())
        {
            if (type.Name == "<Module>" || type.IsInterface) continue;
            if (context.PreservedDecoyTypes.Contains(type)) continue;

            bool typeAttrExcluded = HasObfuscationExclusion(type, out bool applyToMembers);
            if (typeAttrExcluded && applyToMembers) continue;

            foreach (var method in type.Methods)
            {
                if (!CanRenameMethod(method, keepPublic, excludes)) continue;
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
                if (!CanRenameField(field, keepPublic, excludes)) continue;
                Record(context, $"F:{field.FullName}", out var newName, gen);
                field.Name = newName;
                fields++;
            }

            if (!typeAttrExcluded && CanRenameType(type, keepPublic, excludes))
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

    private static bool CanRenameType(
        TypeDefinition t, bool keepPublic, IReadOnlyList<Regex> excludes)
    {
        if (t.Name == "<Module>") return false;
        if (keepPublic && (t.IsPublic || t.IsNestedPublic || t.IsNestedFamily
                           || t.IsNestedFamilyOrAssembly)) return false;
        if (MatchesExclude(t, excludes)) return false;
        return true;
    }

    private static bool CanRenameMethod(
        MethodDefinition m, bool keepPublic, IReadOnlyList<Regex> excludes)
    {
        if (m.IsConstructor || m.IsRuntimeSpecialName) return false;
        if (m.IsGetter || m.IsSetter || m.IsAddOn || m.IsRemoveOn || m.IsFire) return false;
        if (m.IsVirtual || m.IsAbstract || m.HasOverrides) return false;
        if (m.HasPInvokeInfo) return false;
        if (keepPublic && (m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly)) return false;
        if (HasObfuscationExclusion(m, out _)) return false;
        if (MatchesExclude(m, excludes)) return false;
        return true;
    }

    private static bool CanRenameField(
        FieldDefinition f, bool keepPublic, IReadOnlyList<Regex> excludes)
    {
        if (f.IsRuntimeSpecialName || f.IsSpecialName) return false;
        if (keepPublic && (f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly)) return false;
        if (HasObfuscationExclusion(f, out _)) return false;
        if (MatchesExclude(f, excludes)) return false;
        return true;
    }

    private static IReadOnlyList<Regex> CompilePatterns(IReadOnlyList<string> raw)
    {
        if (raw.Count == 0) return Array.Empty<Regex>();
        var list = new List<Regex>(raw.Count);
        foreach (var p in raw)
        {
            if (string.IsNullOrWhiteSpace(p)) continue;
            var pattern = "^" + Regex.Escape(p.Trim()).Replace("\\*", ".*") + "$";
            list.Add(new Regex(pattern, RegexOptions.CultureInvariant));
        }
        return list;
    }

    private static bool MatchesExclude(IMemberDefinition member, IReadOnlyList<Regex> excludes)
    {
        if (excludes.Count == 0) return false;
        var simple = member.Name;
        var full = member.FullName;
        var qualified = member.DeclaringType is { } dt ? $"{dt.FullName}.{member.Name}" : full;
        var shortQualified = member.DeclaringType is { } sdt ? $"{sdt.Name}.{member.Name}" : simple;

        foreach (var rx in excludes)
        {
            if (rx.IsMatch(simple) || rx.IsMatch(full)
                || rx.IsMatch(qualified) || rx.IsMatch(shortQualified))
                return true;
        }
        return false;
    }

    private static bool HasObfuscationExclusion(
        ICustomAttributeProvider provider, out bool applyToMembers)
    {
        applyToMembers = true;
        if (!provider.HasCustomAttributes) return false;
        foreach (var attr in provider.CustomAttributes)
        {
            if (attr.AttributeType.FullName != "System.Reflection.ObfuscationAttribute")
                continue;
            bool exclude = true;
            foreach (var prop in attr.Properties)
            {
                if (prop.Name == "Exclude" && prop.Argument.Value is bool b)
                    exclude = b;
                else if (prop.Name == "ApplyToMembers" && prop.Argument.Value is bool m)
                    applyToMembers = m;
            }
            if (exclude) return true;
        }
        return false;
    }
}
