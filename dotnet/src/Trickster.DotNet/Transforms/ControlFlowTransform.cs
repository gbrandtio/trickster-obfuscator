using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Conservative control-flow obfuscation. Prepends an opaque always-true predicate at each
/// method entry that branches to the real body; the never-taken branch contains a decoy
/// `throw`. This is verifiable IL (the stack is empty at entry) and ties into the
/// entangled-decoy story: deciding the branch statically requires solving the predicate.
/// </summary>
public sealed class ControlFlowTransform : DotNetTransform
{
    public override string Name => "control-flow";

    public override void Apply(DotNetObfuscationContext context)
    {
        var opaque = context.Config.Features.ControlFlow.OpaquePredicates;
        if (!opaque)
        {
            context.Logger.Info("control-flow: opaque predicates disabled, nothing to do");
            return;
        }

        var exCtor = context.Module.ImportReference(
            typeof(Exception).GetConstructor(Type.EmptyTypes));

        int guarded = 0;
        foreach (var type in context.Module.GetTypes())
        foreach (var method in type.Methods)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0) continue;
            if (method.IsConstructor && method.IsStatic) continue; // leave .cctor alone
            GuardMethod(method, exCtor, context.Entropy);
            guarded++;
        }
        context.Logger.Info($"control-flow: guarded {guarded} method(s)");
    }

    private static void GuardMethod(
        MethodDefinition method, MethodReference exCtor, Core.Entropy.EntropySource entropy)
    {
        var il = method.Body.GetILProcessor();
        method.Body.SimplifyMacros();
        var origFirst = method.Body.Instructions[0];

        // Opaque predicate: (n*n - n) % 2 == 0  is always true for any integer n.
        int n = entropy.NextInt(3, 100000);

        var seq = new List<Instruction>
        {
            il.Create(OpCodes.Ldc_I4, n),
            il.Create(OpCodes.Ldc_I4, n),
            il.Create(OpCodes.Mul),
            il.Create(OpCodes.Ldc_I4, n),
            il.Create(OpCodes.Sub),
            il.Create(OpCodes.Ldc_I4_2),
            il.Create(OpCodes.Rem),
            il.Create(OpCodes.Ldc_I4_0),
            il.Create(OpCodes.Ceq),
            il.Create(OpCodes.Brtrue, origFirst),  // always taken -> real body
            il.Create(OpCodes.Newobj, exCtor),     // decoy, never executed
            il.Create(OpCodes.Throw),
        };

        foreach (var instr in seq)
            il.InsertBefore(origFirst, instr);

        method.Body.OptimizeMacros();
    }
}
