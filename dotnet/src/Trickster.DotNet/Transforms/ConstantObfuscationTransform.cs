using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Replaces integer literals (<c>ldc.i4</c>/<c>ldc.i8</c>) with equivalent inline arithmetic so the
/// original constant is absent from the static form. A static analyzer (or an LLM) sees a computed
/// expression rather than the magic number / table size / flag mask. The rewrite is inline (no helper
/// call), so method bodies stay self-contained and later tiers (virtualization, control-flow) are
/// unaffected. Runs before string encryption so it never touches that tier's emitted byte arrays.
/// </summary>
public sealed class ConstantObfuscationTransform : DotNetTransform
{
    public override string Name => "constant-obfuscation";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var chance = context.Config.Features.Constants.RewriteChance;
        var entropy = context.Entropy;

        int rewritten = 0;
        foreach (var type in module.GetTypes())
        foreach (var method in type.Methods)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0) continue;
            rewritten += RewriteMethod(method, chance, entropy);
        }
        context.Logger.Info($"constant-obfuscation: rewrote {rewritten} integer literal(s)");
    }

    private static int RewriteMethod(MethodDefinition method, int chance, Core.Entropy.EntropySource entropy)
    {
        var body = method.Body;
        body.SimplifyMacros(); // collapses ldc.i4.0..8/m1/s into ldc.i4 so every int literal is uniform

        // Snapshot targets before mutating; inserted instructions must not be reprocessed.
        var sites = body.Instructions
            .Where(i => i.OpCode == OpCodes.Ldc_I4 || i.OpCode == OpCodes.Ldc_I8)
            .ToList();

        var il = body.GetILProcessor();
        int count = 0;
        foreach (var site in sites)
        {
            if (entropy.NextInt(100) >= chance) continue;
            if (site.OpCode == OpCodes.Ldc_I4)
                RewriteI4(il, site, unchecked((int)Convert.ToInt64(site.Operand)), entropy);
            else
                RewriteI8(il, site, Convert.ToInt64(site.Operand), entropy);
            count++;
        }

        body.OptimizeMacros();
        return count;
    }

    // Three stack-neutral 32-bit identities (each pushes two constants + one binop => one int out).
    // The original instruction is mutated in place so any branch targeting it stays valid.
    private static void RewriteI4(ILProcessor il, Instruction site, int v, Core.Entropy.EntropySource e)
    {
        int k = unchecked((int)e.NextUInt64());
        switch (e.NextInt(3))
        {
            case 0: // v = (v ^ k) ^ k
                site.OpCode = OpCodes.Ldc_I4; site.Operand = unchecked(v ^ k);
                InsertAfter(il, site, il.Create(OpCodes.Ldc_I4, k), il.Create(OpCodes.Xor));
                break;
            case 1: // v = a + b, a + b == v (mod 2^32)
                site.OpCode = OpCodes.Ldc_I4; site.Operand = k;
                InsertAfter(il, site, il.Create(OpCodes.Ldc_I4, unchecked(v - k)), il.Create(OpCodes.Add));
                break;
            default: // v = a - b, a - b == v (mod 2^32)
                site.OpCode = OpCodes.Ldc_I4; site.Operand = k;
                InsertAfter(il, site, il.Create(OpCodes.Ldc_I4, unchecked(k - v)), il.Create(OpCodes.Sub));
                break;
        }
    }

    private static void RewriteI8(ILProcessor il, Instruction site, long v, Core.Entropy.EntropySource e)
    {
        long k = unchecked((long)e.NextUInt64());
        site.OpCode = OpCodes.Ldc_I8; site.Operand = unchecked(v ^ k);
        InsertAfter(il, site, il.Create(OpCodes.Ldc_I8, k), il.Create(OpCodes.Xor));
    }

    private static void InsertAfter(ILProcessor il, Instruction anchor, params Instruction[] seq)
    {
        foreach (var instr in seq)
        {
            il.InsertAfter(anchor, instr);
            anchor = instr;
        }
    }
}
