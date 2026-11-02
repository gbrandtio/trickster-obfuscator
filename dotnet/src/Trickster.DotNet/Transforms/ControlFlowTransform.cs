using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Control-flow obfuscation tier:
/// <list type="bullet">
/// <item><description>Indirect call dispatch (<c>indirectDispatch</c>): routes intra-module static calls through delegate fields initialized in a helper static constructor.</description></item>
/// <item><description>Whole-method control-flow flattening (<c>flatten</c>): partitions eligible methods into zero-stack basic blocks dispatched inside a shuffled <c>switch</c> state machine.</description></item>
/// <item><description>Entry opaque predicates (<c>opaquePredicates</c>): prepends an always-true arithmetic predicate at method entry whose never-taken branch is a decoy <c>throw</c>.</description></item>
/// </list>
/// </summary>
public sealed class ControlFlowTransform : DotNetTransform
{
    public override string Name => "control-flow";

    public override void Apply(DotNetObfuscationContext context)
    {
        var opts = context.Config.Features.ControlFlow;
        if (!opts.OpaquePredicates && !opts.Flatten && !opts.IndirectDispatch)
        {
            context.Logger.Info("control-flow: all sub-options disabled, nothing to do");
            return;
        }

        int dispatched = 0;
        if (opts.IndirectDispatch)
            dispatched = ApplyIndirectDispatch(context);

        var exCtor = context.Module.ImportReference(
            typeof(Exception).GetConstructor(Type.EmptyTypes));

        int flattened = 0;
        int guarded = 0;
        foreach (var type in context.Module.GetTypes())
        foreach (var method in type.Methods)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0) continue;
            if (method.IsConstructor && method.IsStatic) continue; // leave .cctor alone

            if (opts.Flatten && TryFlattenMethod(method, exCtor, context.Entropy))
                flattened++;

            if (opts.OpaquePredicates)
            {
                GuardMethod(method, exCtor, context.Entropy);
                guarded++;
            }
        }

        context.Logger.Info(
            $"control-flow: guarded {guarded} method(s), flattened {flattened} method(s), indirect-dispatched {dispatched} call(s)");
    }

    private static void GuardMethod(
        MethodDefinition method, MethodReference exCtor, Core.Entropy.EntropySource entropy)
    {
        var il = method.Body.GetILProcessor();
        method.Body.SimplifyMacros();
        var origFirst = method.Body.Instructions[0];

        // Opaque predicate: (n*n - n) % 2 == 0 is always true for any integer n.
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

    private static bool TryFlattenMethod(
        MethodDefinition method, MethodReference exCtor, Core.Entropy.EntropySource entropy)
    {
        if (method.IsConstructor) return false;
        if (method.Body.ExceptionHandlers.Count > 0) return false;

        method.Body.SimplifyMacros();
        var ins = method.Body.Instructions;
        int n = ins.Count;
        if (n < 4)
        {
            method.Body.OptimizeMacros();
            return false;
        }

        for (int i = 0; i < n; i++)
        {
            if (ins[i].OpCode == OpCodes.Switch)
            {
                method.Body.OptimizeMacros();
                return false;
            }
        }

        if (!TryComputeStackBefore(method, out var stackBefore))
        {
            method.Body.OptimizeMacros();
            return false;
        }

        var indexOf = new Dictionary<Instruction, int>(n);
        var branchTargets = new HashSet<int>();
        for (int i = 0; i < n; i++)
            indexOf[ins[i]] = i;

        for (int i = 0; i < n; i++)
        {
            if (ins[i].Operand is Instruction target && indexOf.TryGetValue(target, out int ti))
                branchTargets.Add(ti);
        }

        var isStart = new bool[n];
        isStart[0] = true;
        for (int i = 1; i < n; i++)
        {
            if (stackBefore[i] != 0) continue;
            var prev = ins[i - 1].OpCode;
            if (branchTargets.Contains(i)
                || prev.FlowControl == FlowControl.Branch
                || prev.FlowControl == FlowControl.Cond_Branch
                || prev.FlowControl == FlowControl.Return
                || prev.FlowControl == FlowControl.Throw
                || prev == OpCodes.Stloc || prev == OpCodes.Stsfld || prev == OpCodes.Pop)
            {
                isStart[i] = true;
            }
        }

        // Fixed-point closure: ensure that any branch inside a block (not at the end of a block)
        // or targeting an instruction with non-zero stack stays within the same block.
        bool changed = true;
        while (changed)
        {
            changed = false;
            for (int i = 0; i < n; i++)
            {
                if (ins[i].Operand is not Instruction target || !indexOf.TryGetValue(target, out int dst))
                    continue;

                bool isEndOfBlock = (i == n - 1) || isStart[i + 1];
                if (!isEndOfBlock || !isStart[dst])
                {
                    int lo = Math.Min(i, dst) + 1;
                    int hi = Math.Max(i, dst);
                    for (int k = lo; k <= hi; k++)
                    {
                        if (isStart[k])
                        {
                            isStart[k] = false;
                            changed = true;
                        }
                    }
                    // If `i` was a conditional branch that merged with `dst`, `i + 1` must also
                    // stay in the same block if `dst` is not a block start.
                    if (!isStart[dst] && i + 1 < n && isStart[i + 1])
                    {
                        isStart[i + 1] = false;
                        changed = true;
                    }
                }
            }
        }

        var blockStarts = new List<int>();
        for (int i = 0; i < n; i++)
            if (isStart[i])
                blockStarts.Add(i);

        int blockCount = blockStarts.Count;
        if (blockCount < 2)
        {
            method.Body.OptimizeMacros();
            return false;
        }

        var startToBlock = new Dictionary<Instruction, int>(blockCount);
        var blocks = new List<List<Instruction>>(blockCount);
        for (int b = 0; b < blockCount; b++)
        {
            int s = blockStarts[b];
            int e = (b + 1 < blockCount) ? blockStarts[b + 1] : n;
            startToBlock[ins[s]] = b;
            var list = new List<Instruction>(e - s);
            for (int i = s; i < e; i++)
                list.Add(ins[i]);
            blocks.Add(list);
        }

        var il = method.Body.GetILProcessor();
        var stateVar = new VariableDefinition(method.Module.TypeSystem.Int32);
        method.Body.Variables.Add(stateVar);
        method.Body.InitLocals = true;

        int mask = entropy.NextInt(1000, 1000000);
        var caseForBlock = Shuffle(blockCount, entropy);
        var emitOrder = Shuffle(blockCount, entropy);
        var stateValue = new int[blockCount];
        for (int b = 0; b < blockCount; b++)
            stateValue[b] = caseForBlock[b] ^ mask;

        var dispatchStart = il.Create(OpCodes.Ldloc, stateVar);

        for (int b = 0; b < blockCount; b++)
        {
            var blk = blocks[b];
            var last = blk[^1];
            var op = last.OpCode;

            if (op == OpCodes.Ret || op == OpCodes.Throw)
            {
                continue;
            }

            if (op == OpCodes.Br && last.Operand is Instruction brTarget
                && startToBlock.TryGetValue(brTarget, out int targetBlock))
            {
                // Mutate in place so any intra-block branch targeting `last` stays valid.
                last.OpCode = OpCodes.Ldc_I4;
                last.Operand = stateValue[targetBlock];
                blk.Add(il.Create(OpCodes.Stloc, stateVar));
                blk.Add(il.Create(OpCodes.Br, dispatchStart));
            }
            else if (op.FlowControl == FlowControl.Cond_Branch
                     && last.Operand is Instruction condTarget
                     && startToBlock.TryGetValue(condTarget, out int takenBlock)
                     && b + 1 < blockCount)
            {
                var takenSet = il.Create(OpCodes.Ldc_I4, stateValue[takenBlock]);
                last.Operand = takenSet;
                blk.Add(il.Create(OpCodes.Ldc_I4, stateValue[b + 1]));
                blk.Add(il.Create(OpCodes.Stloc, stateVar));
                blk.Add(il.Create(OpCodes.Br, dispatchStart));
                blk.Add(takenSet);
                blk.Add(il.Create(OpCodes.Stloc, stateVar));
                blk.Add(il.Create(OpCodes.Br, dispatchStart));
            }
            else if (b + 1 < blockCount)
            {
                blk.Add(il.Create(OpCodes.Ldc_I4, stateValue[b + 1]));
                blk.Add(il.Create(OpCodes.Stloc, stateVar));
                blk.Add(il.Create(OpCodes.Br, dispatchStart));
            }
        }

        var switchTargets = new Instruction[blockCount];
        for (int b = 0; b < blockCount; b++)
            switchTargets[caseForBlock[b]] = blocks[b][0];

        ins.Clear();
        ins.Add(il.Create(OpCodes.Ldc_I4, stateValue[0]));
        ins.Add(il.Create(OpCodes.Stloc, stateVar));
        ins.Add(il.Create(OpCodes.Br, dispatchStart));

        ins.Add(dispatchStart);
        ins.Add(il.Create(OpCodes.Ldc_I4, mask));
        ins.Add(il.Create(OpCodes.Xor));
        ins.Add(il.Create(OpCodes.Switch, switchTargets));
        ins.Add(il.Create(OpCodes.Newobj, exCtor));
        ins.Add(il.Create(OpCodes.Throw));

        foreach (int b in emitOrder)
        foreach (var instr in blocks[b])
            ins.Add(instr);

        method.Body.OptimizeMacros();
        return true;
    }

    private static int[] Shuffle(int count, Core.Entropy.EntropySource entropy)
    {
        var arr = new int[count];
        for (int i = 0; i < count; i++) arr[i] = i;
        for (int i = count - 1; i > 0; i--)
        {
            int j = entropy.NextInt(i + 1);
            (arr[i], arr[j]) = (arr[j], arr[i]);
        }
        return arr;
    }

    private static bool TryComputeStackBefore(MethodDefinition method, out int[] stackBefore)
    {
        var ins = method.Body.Instructions;
        int n = ins.Count;
        stackBefore = new int[n];
        Array.Fill(stackBefore, -1);

        var indexOf = new Dictionary<Instruction, int>(n);
        for (int i = 0; i < n; i++) indexOf[ins[i]] = i;

        var queue = new Queue<int>();
        stackBefore[0] = 0;
        queue.Enqueue(0);

        while (queue.Count > 0)
        {
            int i = queue.Dequeue();
            int cur = stackBefore[i];
            if (!TryGetStackDelta(method, ins[i], out int pop, out int push))
                return false;
            if (cur < pop)
                return false;

            int after = cur - pop + push;
            var op = ins[i].OpCode;

            switch (op.FlowControl)
            {
                case FlowControl.Next:
                case FlowControl.Call:
                    if (!Propagate(i + 1, after, n, stackBefore, queue)) return false;
                    break;
                case FlowControl.Branch:
                    if (ins[i].Operand is not Instruction bt || !indexOf.TryGetValue(bt, out int bi))
                        return false;
                    if (!Propagate(bi, after, n, stackBefore, queue)) return false;
                    break;
                case FlowControl.Cond_Branch:
                    if (ins[i].Operand is not Instruction ct || !indexOf.TryGetValue(ct, out int ci))
                        return false;
                    if (!Propagate(i + 1, after, n, stackBefore, queue)) return false;
                    if (!Propagate(ci, after, n, stackBefore, queue)) return false;
                    break;
                case FlowControl.Return:
                case FlowControl.Throw:
                    if (after != 0) return false;
                    break;
                default:
                    return false;
            }
        }

        for (int i = 0; i < n; i++)
            if (stackBefore[i] < 0)
                return false;

        return true;
    }

    private static bool Propagate(int target, int height, int n, int[] stackBefore, Queue<int> queue)
    {
        if (target < 0 || target >= n) return false;
        if (stackBefore[target] == -1)
        {
            stackBefore[target] = height;
            queue.Enqueue(target);
            return true;
        }
        return stackBefore[target] == height;
    }

    private static bool TryGetStackDelta(MethodDefinition method, Instruction ins, out int pop, out int push)
    {
        pop = 0;
        push = 0;
        var code = ins.OpCode.Code;
        switch (code)
        {
            case Code.Nop:
            case Code.Br:
                return true;

            case Code.Ldc_I4:
            case Code.Ldc_I8:
            case Code.Ldc_R4:
            case Code.Ldc_R8:
            case Code.Ldstr:
            case Code.Ldnull:
            case Code.Ldarg:
            case Code.Ldarga:
            case Code.Ldloc:
            case Code.Ldloca:
            case Code.Ldsfld:
            case Code.Ldsflda:
            case Code.Ldftn:
            case Code.Ldtoken:
                push = 1;
                return true;

            case Code.Dup:
                pop = 1;
                push = 2;
                return true;

            case Code.Pop:
            case Code.Stloc:
            case Code.Starg:
            case Code.Stsfld:
            case Code.Throw:
            case Code.Brtrue:
            case Code.Brfalse:
            case Code.Initobj:
                pop = 1;
                return true;

            case Code.Beq:
            case Code.Bge:
            case Code.Bge_Un:
            case Code.Bgt:
            case Code.Bgt_Un:
            case Code.Ble:
            case Code.Ble_Un:
            case Code.Blt:
            case Code.Blt_Un:
            case Code.Bne_Un:
            case Code.Stfld:
                pop = 2;
                return true;

            case Code.Add:
            case Code.Add_Ovf:
            case Code.Add_Ovf_Un:
            case Code.Sub:
            case Code.Sub_Ovf:
            case Code.Sub_Ovf_Un:
            case Code.Mul:
            case Code.Mul_Ovf:
            case Code.Mul_Ovf_Un:
            case Code.Div:
            case Code.Div_Un:
            case Code.Rem:
            case Code.Rem_Un:
            case Code.And:
            case Code.Or:
            case Code.Xor:
            case Code.Shl:
            case Code.Shr:
            case Code.Shr_Un:
            case Code.Ceq:
            case Code.Cgt:
            case Code.Cgt_Un:
            case Code.Clt:
            case Code.Clt_Un:
            case Code.Ldelem_Any:
            case Code.Ldelem_I:
            case Code.Ldelem_I1:
            case Code.Ldelem_I2:
            case Code.Ldelem_I4:
            case Code.Ldelem_I8:
            case Code.Ldelem_R4:
            case Code.Ldelem_R8:
            case Code.Ldelem_Ref:
            case Code.Ldelem_U1:
            case Code.Ldelem_U2:
            case Code.Ldelem_U4:
            case Code.Ldelema:
                pop = 2;
                push = 1;
                return true;

            case Code.Neg:
            case Code.Not:
            case Code.Conv_I:
            case Code.Conv_I1:
            case Code.Conv_I2:
            case Code.Conv_I4:
            case Code.Conv_I8:
            case Code.Conv_U:
            case Code.Conv_U1:
            case Code.Conv_U2:
            case Code.Conv_U4:
            case Code.Conv_U8:
            case Code.Conv_R4:
            case Code.Conv_R8:
            case Code.Ldlen:
            case Code.Ldfld:
            case Code.Ldflda:
            case Code.Box:
            case Code.Unbox_Any:
            case Code.Isinst:
            case Code.Castclass:
            case Code.Newarr:
                pop = 1;
                push = 1;
                return true;

            case Code.Stelem_Any:
            case Code.Stelem_I:
            case Code.Stelem_I1:
            case Code.Stelem_I2:
            case Code.Stelem_I4:
            case Code.Stelem_I8:
            case Code.Stelem_R4:
            case Code.Stelem_R8:
            case Code.Stelem_Ref:
                pop = 3;
                return true;

            case Code.Newobj:
                if (ins.Operand is not IMethodSignature ctorSig) return false;
                pop = ctorSig.Parameters.Count;
                push = 1;
                return true;

            case Code.Call:
            case Code.Callvirt:
                if (ins.Operand is not IMethodSignature callSig) return false;
                pop = callSig.Parameters.Count + (callSig.HasThis && !callSig.ExplicitThis ? 1 : 0);
                push = callSig.ReturnType.MetadataType == MetadataType.Void ? 0 : 1;
                return true;

            case Code.Ret:
                pop = method.ReturnType.MetadataType == MetadataType.Void ? 0 : 1;
                push = 0;
                return true;

            default:
                return false;
        }
    }

    private static int ApplyIndirectDispatch(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;

        var existingTypes = module.GetTypes().ToList();
        var eligibleTargets = new HashSet<MethodDefinition>();
        foreach (var t in existingTypes)
        {
            if (t.Name == "<Module>" || t.IsInterface || t.HasGenericParameters) continue;
            foreach (var m in t.Methods)
            {
                if (IsDispatchTargetEligible(m))
                    eligibleTargets.Add(m);
            }
        }

        if (eligibleTargets.Count == 0) return 0;

        TypeDefinition? holder = null;
        MethodDefinition? holderCctor = null;
        ILProcessor? cctorIl = null;
        Instruction? cctorRet = null;
        var slots = new Dictionary<MethodDefinition, (FieldDefinition Field, MethodReference Invoke)>();

        int rewritten = 0;
        foreach (var type in existingTypes)
        foreach (var method in type.Methods)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0) continue;
            if (method.IsConstructor && method.IsStatic) continue;

            var callSites = method.Body.Instructions
                .Where(i => i.OpCode == OpCodes.Call
                            && i.Operand is MethodDefinition target
                            && target != method
                            && eligibleTargets.Contains(target))
                .ToList();

            if (callSites.Count == 0) continue;

            method.Body.SimplifyMacros();
            var il = method.Body.GetILProcessor();

            foreach (var site in callSites)
            {
                var target = (MethodDefinition)site.Operand;
                if (!slots.TryGetValue(target, out var slot))
                {
                    if (holder is null)
                    {
                        holder = new TypeDefinition(
                            string.Empty, gen.Next(),
                            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                                | TypeAttributes.Abstract,
                            module.TypeSystem.Object);
                        holderCctor = new MethodDefinition(
                            ".cctor",
                            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig
                                | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                            module.TypeSystem.Void);
                        cctorIl = holderCctor.Body.GetILProcessor();
                        cctorRet = cctorIl.Create(OpCodes.Ret);
                        cctorIl.Append(cctorRet);
                        holder.Methods.Add(holderCctor);
                        module.Types.Add(holder);
                    }

                    slot = CreateDelegateSlot(module, holder, cctorIl!, cctorRet!, gen, target);
                    slots[target] = slot;
                }

                RewriteCallSiteToDelegate(method, il, site, target, slot.Field, slot.Invoke);
                rewritten++;
            }

            method.Body.OptimizeMacros();
        }

        return rewritten;
    }

    private static bool IsDispatchTargetEligible(MethodDefinition m)
    {
        if (!m.IsStatic || !m.HasBody) return false;
        if (m.IsConstructor || m.IsRuntimeSpecialName || m.IsSpecialName) return false;
        if (m.HasGenericParameters || m.HasPInvokeInfo) return false;
        if (m.Parameters.Count > 4) return false;

        var ret = m.ReturnType;
        if (ret.IsByReference || ret.IsPointer || ret.IsGenericParameter) return false;
        foreach (var p in m.Parameters)
        {
            var pt = p.ParameterType;
            if (pt.IsByReference || pt.IsPointer || pt.IsGenericParameter) return false;
        }
        return true;
    }

    private static (FieldDefinition Field, MethodReference Invoke) CreateDelegateSlot(
        ModuleDefinition module, TypeDefinition holder, ILProcessor cctorIl, Instruction cctorRet,
        Naming.NameGenerator gen, MethodDefinition target)
    {
        if (target.IsPrivate)
            target.IsAssembly = true;

        bool isVoid = target.ReturnType.MetadataType == MetadataType.Void;
        int arity = target.Parameters.Count;

        TypeReference fieldType;
        MethodReference ctorRef;
        MethodReference invokeRef;

        if (isVoid && arity == 0)
        {
            fieldType = module.ImportReference(typeof(Action));
            ctorRef = module.ImportReference(
                typeof(Action).GetConstructor(new[] { typeof(object), typeof(IntPtr) }));
            invokeRef = module.ImportReference(typeof(Action).GetMethod("Invoke"));
        }
        else
        {
            Type openClrType = isVoid
                ? arity switch
                {
                    1 => typeof(Action<>),
                    2 => typeof(Action<,>),
                    3 => typeof(Action<,,>),
                    _ => typeof(Action<,,,>),
                }
                : arity switch
                {
                    0 => typeof(Func<>),
                    1 => typeof(Func<,>),
                    2 => typeof(Func<,,>),
                    3 => typeof(Func<,,,>),
                    _ => typeof(Func<,,,,>),
                };

            var openRef = module.ImportReference(openClrType);
            var genericInst = new GenericInstanceType(openRef);
            foreach (var p in target.Parameters)
                genericInst.GenericArguments.Add(p.ParameterType);
            if (!isVoid)
                genericInst.GenericArguments.Add(target.ReturnType);

            fieldType = genericInst;
            ctorRef = new MethodReference(".ctor", module.TypeSystem.Void, genericInst)
            {
                HasThis = true,
            };
            ctorRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.Object));
            ctorRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.IntPtr));

            invokeRef = new MethodReference(
                "Invoke",
                isVoid ? module.TypeSystem.Void : openRef.GenericParameters[arity],
                genericInst)
            {
                HasThis = true,
            };
            for (int i = 0; i < arity; i++)
                invokeRef.Parameters.Add(new ParameterDefinition(openRef.GenericParameters[i]));
        }

        var field = new FieldDefinition(
            gen.Next(),
            FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.InitOnly,
            fieldType);
        holder.Fields.Add(field);

        cctorIl.InsertBefore(cctorRet, cctorIl.Create(OpCodes.Ldnull));
        cctorIl.InsertBefore(cctorRet, cctorIl.Create(OpCodes.Ldftn, target));
        cctorIl.InsertBefore(cctorRet, cctorIl.Create(OpCodes.Newobj, ctorRef));
        cctorIl.InsertBefore(cctorRet, cctorIl.Create(OpCodes.Stsfld, field));

        return (field, invokeRef);
    }

    private static void RewriteCallSiteToDelegate(
        MethodDefinition caller, ILProcessor il, Instruction callSite,
        MethodDefinition target, FieldDefinition delegateField, MethodReference invokeRef)
    {
        int arity = target.Parameters.Count;
        if (arity == 0)
        {
            callSite.OpCode = OpCodes.Ldsfld;
            callSite.Operand = delegateField;
            il.InsertAfter(callSite, il.Create(OpCodes.Callvirt, invokeRef));
            return;
        }

        caller.Body.InitLocals = true;
        var temps = new VariableDefinition[arity];
        for (int i = 0; i < arity; i++)
        {
            temps[i] = new VariableDefinition(target.Parameters[i].ParameterType);
            caller.Body.Variables.Add(temps[i]);
        }

        // Mutate `callSite` in place to pop the last argument, keeping branch targets intact.
        callSite.OpCode = OpCodes.Stloc;
        callSite.Operand = temps[arity - 1];

        var anchor = callSite;
        for (int i = arity - 2; i >= 0; i--)
        {
            var st = il.Create(OpCodes.Stloc, temps[i]);
            il.InsertAfter(anchor, st);
            anchor = st;
        }

        var ldField = il.Create(OpCodes.Ldsfld, delegateField);
        il.InsertAfter(anchor, ldField);
        anchor = ldField;

        for (int i = 0; i < arity; i++)
        {
            var ld = il.Create(OpCodes.Ldloc, temps[i]);
            il.InsertAfter(anchor, ld);
            anchor = ld;
        }

        il.InsertAfter(anchor, il.Create(OpCodes.Callvirt, invokeRef));
    }
}
