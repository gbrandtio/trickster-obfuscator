using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Method virtualization tier. Translates eligible integer/boolean methods into a custom
/// per-build randomized 2-word bytecode array (<c>int[]</c>) encrypted with a per-build key,
/// and replaces each method body with a stub that invokes an injected stack-machine
/// interpreter.
/// </summary>
public sealed class MethodVirtualizationTransform : DotNetTransform
{
    private enum VmOp
    {
        Nop = 0,
        Ldc,
        Ldarg,
        Starg,
        Ldloc,
        Stloc,
        Dup,
        Pop,
        Add,
        Sub,
        Mul,
        Div,
        Rem,
        And,
        Or,
        Xor,
        Neg,
        Ceq,
        Cgt,
        Clt,
        Br,
        Brtrue,
        Brfalse,
        Ret,
        Count
    }

    public override string Name => "virtualization";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;
        var entropy = context.Entropy;

        context.Artifacts.TryGet(ArtifactKeys.PreservedDecoyTypes, out var preservedDecoys);
        var opcodeMap = BuildRandomizedOpcodeMap(entropy);
        int codeKey = entropy.NextInt(0x1000, 0x7FFF0000);

        var candidates = new List<(MethodDefinition Method, int[] Bytecode, int LocalCount)>();
        foreach (var type in module.GetTypes().ToList())
        {
            if (type.Name == "<Module>" || type.IsInterface || type.HasGenericParameters) continue;
            if (preservedDecoys is not null && preservedDecoys.Contains(type)) continue;

            foreach (var method in type.Methods)
            {
                if (!IsEligible(method)) continue;
                if (TryCompile(method, opcodeMap, codeKey, out var bytecode, out int localCount))
                    candidates.Add((method, bytecode, localCount));
            }
        }

        if (candidates.Count == 0)
        {
            context.Logger.Info("virtualization: no eligible methods found");
            return;
        }

        var vmExecute = BuildInterpreter(module, gen.Next(), gen.Next(), opcodeMap, codeKey);
        module.Types.Add(vmExecute.DeclaringType);

        foreach (var (method, bytecode, localCount) in candidates)
            RewriteToVmStub(module, method, vmExecute, bytecode, localCount);

        context.Logger.Info($"virtualization: virtualized {candidates.Count} method(s)");
    }

    private static int[] BuildRandomizedOpcodeMap(Core.Entropy.EntropySource entropy)
    {
        int count = (int)VmOp.Count;
        var map = new int[count];
        var used = new HashSet<int>();
        for (int i = 0; i < count; i++)
        {
            int code;
            do
            {
                code = entropy.NextInt(10, 10000);
            } while (!used.Add(code));
            map[i] = code;
        }
        return map;
    }

    private static bool IsEligible(MethodDefinition m)
    {
        if (!m.HasBody || m.Body.Instructions.Count == 0) return false;
        if (m.IsConstructor || m.IsRuntimeSpecialName || m.IsSpecialName) return false;
        if (m.IsVirtual || m.IsAbstract || m.HasOverrides || m.HasPInvokeInfo) return false;
        if (m.HasGenericParameters || m.Body.ExceptionHandlers.Count > 0) return false;
        if (ReferenceEquals(m.Module.EntryPoint, m)) return false;

        if (!IsIntCompatible(m.ReturnType)) return false;
        if (m.HasThis) return false;
        foreach (var p in m.Parameters)
            if (!IsIntCompatible(p.ParameterType)) return false;
        foreach (var v in m.Body.Variables)
            if (!IsIntCompatible(v.VariableType)) return false;

        return true;
    }

    private static bool IsIntCompatible(TypeReference t)
    {
        if (t.IsByReference || t.IsPointer || t.IsGenericParameter) return false;
        return t.MetadataType is MetadataType.Int32 or MetadataType.Boolean
            or MetadataType.Byte or MetadataType.SByte
            or MetadataType.Int16 or MetadataType.UInt16;
    }

    private static bool TryCompile(
        MethodDefinition method, int[] opcodeMap, int key,
        out int[] bytecode, out int localCount)
    {
        bytecode = Array.Empty<int>();
        localCount = method.Body.Variables.Count;

        method.Body.SimplifyMacros();
        var ins = method.Body.Instructions;
        int n = ins.Count;

        var vmOffsetOf = new Dictionary<Instruction, int>(n);
        var words = new List<(VmOp Op, int Arg, Instruction? BranchTarget)>();

        for (int i = 0; i < n; i++)
        {
            var cur = ins[i];
            vmOffsetOf[cur] = words.Count * 2;
            var code = cur.OpCode.Code;

            switch (code)
            {
                case Code.Nop:
                    words.Add((VmOp.Nop, 0, null));
                    break;
                case Code.Ldc_I4:
                    words.Add((VmOp.Ldc, (int)cur.Operand, null));
                    break;
                case Code.Ldarg:
                    words.Add((VmOp.Ldarg, ((ParameterDefinition)cur.Operand).Index, null));
                    break;
                case Code.Starg:
                    words.Add((VmOp.Starg, ((ParameterDefinition)cur.Operand).Index, null));
                    break;
                case Code.Ldloc:
                    words.Add((VmOp.Ldloc, ((VariableDefinition)cur.Operand).Index, null));
                    break;
                case Code.Stloc:
                    words.Add((VmOp.Stloc, ((VariableDefinition)cur.Operand).Index, null));
                    break;
                case Code.Dup:
                    words.Add((VmOp.Dup, 0, null));
                    break;
                case Code.Pop:
                    words.Add((VmOp.Pop, 0, null));
                    break;
                case Code.Add:
                    words.Add((VmOp.Add, 0, null));
                    break;
                case Code.Sub:
                    words.Add((VmOp.Sub, 0, null));
                    break;
                case Code.Mul:
                    words.Add((VmOp.Mul, 0, null));
                    break;
                case Code.Div:
                    words.Add((VmOp.Div, 0, null));
                    break;
                case Code.Rem:
                    words.Add((VmOp.Rem, 0, null));
                    break;
                case Code.And:
                    words.Add((VmOp.And, 0, null));
                    break;
                case Code.Or:
                    words.Add((VmOp.Or, 0, null));
                    break;
                case Code.Xor:
                    words.Add((VmOp.Xor, 0, null));
                    break;
                case Code.Neg:
                    words.Add((VmOp.Neg, 0, null));
                    break;
                case Code.Ceq:
                    words.Add((VmOp.Ceq, 0, null));
                    break;
                case Code.Cgt:
                    words.Add((VmOp.Cgt, 0, null));
                    break;
                case Code.Clt:
                    words.Add((VmOp.Clt, 0, null));
                    break;
                case Code.Br:
                    words.Add((VmOp.Br, 0, (Instruction)cur.Operand));
                    break;
                case Code.Brtrue:
                    words.Add((VmOp.Brtrue, 0, (Instruction)cur.Operand));
                    break;
                case Code.Brfalse:
                    words.Add((VmOp.Brfalse, 0, (Instruction)cur.Operand));
                    break;
                case Code.Beq:
                    words.Add((VmOp.Ceq, 0, null));
                    words.Add((VmOp.Brtrue, 0, (Instruction)cur.Operand));
                    break;
                case Code.Bne_Un:
                    words.Add((VmOp.Ceq, 0, null));
                    words.Add((VmOp.Brfalse, 0, (Instruction)cur.Operand));
                    break;
                case Code.Blt:
                    words.Add((VmOp.Clt, 0, null));
                    words.Add((VmOp.Brtrue, 0, (Instruction)cur.Operand));
                    break;
                case Code.Bge:
                    words.Add((VmOp.Clt, 0, null));
                    words.Add((VmOp.Brfalse, 0, (Instruction)cur.Operand));
                    break;
                case Code.Bgt:
                    words.Add((VmOp.Cgt, 0, null));
                    words.Add((VmOp.Brtrue, 0, (Instruction)cur.Operand));
                    break;
                case Code.Ble:
                    words.Add((VmOp.Cgt, 0, null));
                    words.Add((VmOp.Brfalse, 0, (Instruction)cur.Operand));
                    break;
                case Code.Ret:
                    words.Add((VmOp.Ret, 0, null));
                    break;
                default:
                    method.Body.OptimizeMacros();
                    return false;
            }
        }

        bytecode = new int[words.Count * 2];
        for (int i = 0; i < words.Count; i++)
        {
            var (op, arg, target) = words[i];
            if (target is not null)
            {
                if (!vmOffsetOf.TryGetValue(target, out arg))
                {
                    method.Body.OptimizeMacros();
                    return false;
                }
            }
            bytecode[i * 2] = opcodeMap[(int)op] ^ key;
            bytecode[i * 2 + 1] = arg ^ key;
        }

        return true;
    }

    private static void RewriteToVmStub(
        ModuleDefinition module, MethodDefinition method, MethodReference vmExecute,
        int[] bytecode, int localCount)
    {
        var body = method.Body;
        body.Variables.Clear();
        body.ExceptionHandlers.Clear();
        body.Instructions.Clear();
        body.InitLocals = true;

        var il = body.GetILProcessor();

        // Push int[] code
        il.Emit(OpCodes.Ldc_I4, bytecode.Length);
        il.Emit(OpCodes.Newarr, module.TypeSystem.Int32);
        for (int i = 0; i < bytecode.Length; i++)
        {
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldc_I4, i);
            il.Emit(OpCodes.Ldc_I4, bytecode[i]);
            il.Emit(OpCodes.Stelem_I4);
        }

        // Push int[] args
        int paramCount = method.Parameters.Count;
        il.Emit(OpCodes.Ldc_I4, paramCount);
        il.Emit(OpCodes.Newarr, module.TypeSystem.Int32);
        for (int p = 0; p < paramCount; p++)
        {
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldc_I4, p);
            il.Emit(OpCodes.Ldarg, method.Parameters[p]);
            il.Emit(OpCodes.Stelem_I4);
        }

        // Push localCount and call interpreter
        il.Emit(OpCodes.Ldc_I4, localCount);
        il.Emit(OpCodes.Call, vmExecute);
        il.Emit(OpCodes.Ret);

        body.OptimizeMacros();
    }

    private static MethodDefinition BuildInterpreter(
        ModuleDefinition module, string typeName, string methodName,
        int[] opcodeMap, int key)
    {
        var type = new TypeDefinition(
            string.Empty, typeName,
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var int32 = module.TypeSystem.Int32;
        var int32Arr = new ArrayType(int32);

        var method = new MethodDefinition(
            methodName,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            int32);
        method.Parameters.Add(new ParameterDefinition(int32Arr)); // code
        method.Parameters.Add(new ParameterDefinition(int32Arr)); // args
        method.Parameters.Add(new ParameterDefinition(int32));    // localCount

        var exCtor = module.ImportReference(
            typeof(InvalidOperationException).GetConstructor(Type.EmptyTypes));

        var body = method.Body = new MethodBody(method);
        body.InitLocals = true;

        var stack = new VariableDefinition(int32Arr);
        var locals = new VariableDefinition(int32Arr);
        var sp = new VariableDefinition(int32);
        var pc = new VariableDefinition(int32);
        var op = new VariableDefinition(int32);
        var operand = new VariableDefinition(int32);
        var rhs = new VariableDefinition(int32);
        var lhs = new VariableDefinition(int32);

        body.Variables.Add(stack);
        body.Variables.Add(locals);
        body.Variables.Add(sp);
        body.Variables.Add(pc);
        body.Variables.Add(op);
        body.Variables.Add(operand);
        body.Variables.Add(rhs);
        body.Variables.Add(lhs);

        var il = body.GetILProcessor();

        // stack = new int[64]; locals = new int[localCount]; sp = 0; pc = 0;
        il.Emit(OpCodes.Ldc_I4, 64);
        il.Emit(OpCodes.Newarr, int32);
        il.Emit(OpCodes.Stloc, stack);

        il.Emit(OpCodes.Ldarg_2);
        il.Emit(OpCodes.Newarr, int32);
        il.Emit(OpCodes.Stloc, locals);

        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Stloc, sp);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Stloc, pc);

        var loopHead = il.Create(OpCodes.Ldloc, pc);
        var decode = il.Create(OpCodes.Ldarg_0);

        il.Append(loopHead);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldlen);
        il.Emit(OpCodes.Conv_I4);
        il.Emit(OpCodes.Blt, decode);
        il.Emit(OpCodes.Newobj, exCtor);
        il.Emit(OpCodes.Throw);

        // op = code[pc] ^ key; operand = code[pc + 1] ^ key; pc += 2;
        il.Append(decode);
        il.Emit(OpCodes.Ldloc, pc);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Ldc_I4, key);
        il.Emit(OpCodes.Xor);
        il.Emit(OpCodes.Stloc, op);

        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldloc, pc);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Add);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Ldc_I4, key);
        il.Emit(OpCodes.Xor);
        il.Emit(OpCodes.Stloc, operand);

        il.Emit(OpCodes.Ldloc, pc);
        il.Emit(OpCodes.Ldc_I4_2);
        il.Emit(OpCodes.Add);
        il.Emit(OpCodes.Stloc, pc);

        var handlers = new Dictionary<VmOp, Instruction>();
        foreach (VmOp vmOp in Enum.GetValues<VmOp>())
        {
            if (vmOp == VmOp.Count) continue;
            var label = il.Create(OpCodes.Nop);
            handlers[vmOp] = label;
            il.Emit(OpCodes.Ldloc, op);
            il.Emit(OpCodes.Ldc_I4, opcodeMap[(int)vmOp]);
            il.Emit(OpCodes.Beq, label);
        }

        // Unknown opcode -> throw InvalidOperationException
        il.Emit(OpCodes.Newobj, exCtor);
        il.Emit(OpCodes.Throw);

        // Nop
        il.Append(handlers[VmOp.Nop]);
        il.Emit(OpCodes.Br, loopHead);

        // Ldc: stack[sp++] = operand;
        il.Append(handlers[VmOp.Ldc]);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldloc, operand);
        il.Emit(OpCodes.Stelem_I4);
        EmitInc(il, sp, 1);
        il.Emit(OpCodes.Br, loopHead);

        // Ldarg: stack[sp++] = args[operand];
        il.Append(handlers[VmOp.Ldarg]);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Ldloc, operand);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Stelem_I4);
        EmitInc(il, sp, 1);
        il.Emit(OpCodes.Br, loopHead);

        // Starg: args[operand] = stack[--sp];
        il.Append(handlers[VmOp.Starg]);
        EmitInc(il, sp, -1);
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Ldloc, operand);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Stelem_I4);
        il.Emit(OpCodes.Br, loopHead);

        // Ldloc: stack[sp++] = locals[operand];
        il.Append(handlers[VmOp.Ldloc]);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldloc, locals);
        il.Emit(OpCodes.Ldloc, operand);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Stelem_I4);
        EmitInc(il, sp, 1);
        il.Emit(OpCodes.Br, loopHead);

        // Stloc: locals[operand] = stack[--sp];
        il.Append(handlers[VmOp.Stloc]);
        EmitInc(il, sp, -1);
        il.Emit(OpCodes.Ldloc, locals);
        il.Emit(OpCodes.Ldloc, operand);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Stelem_I4);
        il.Emit(OpCodes.Br, loopHead);

        // Dup: stack[sp] = stack[sp - 1]; sp++;
        il.Append(handlers[VmOp.Dup]);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Sub);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Stelem_I4);
        EmitInc(il, sp, 1);
        il.Emit(OpCodes.Br, loopHead);

        // Pop: sp--;
        il.Append(handlers[VmOp.Pop]);
        EmitInc(il, sp, -1);
        il.Emit(OpCodes.Br, loopHead);

        // Binary operations
        EmitBinOp(il, handlers[VmOp.Add], OpCodes.Add, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Sub], OpCodes.Sub, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Mul], OpCodes.Mul, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Div], OpCodes.Div, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Rem], OpCodes.Rem, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.And], OpCodes.And, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Or], OpCodes.Or, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Xor], OpCodes.Xor, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Ceq], OpCodes.Ceq, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Cgt], OpCodes.Cgt, stack, sp, lhs, rhs, loopHead);
        EmitBinOp(il, handlers[VmOp.Clt], OpCodes.Clt, stack, sp, lhs, rhs, loopHead);

        // Neg: stack[sp - 1] = -stack[sp - 1];
        il.Append(handlers[VmOp.Neg]);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Sub);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Sub);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Neg);
        il.Emit(OpCodes.Stelem_I4);
        il.Emit(OpCodes.Br, loopHead);

        // Br: pc = operand;
        il.Append(handlers[VmOp.Br]);
        il.Emit(OpCodes.Ldloc, operand);
        il.Emit(OpCodes.Stloc, pc);
        il.Emit(OpCodes.Br, loopHead);

        // Brtrue: if (stack[--sp] != 0) pc = operand;
        il.Append(handlers[VmOp.Brtrue]);
        EmitInc(il, sp, -1);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Brfalse, loopHead);
        il.Emit(OpCodes.Ldloc, operand);
        il.Emit(OpCodes.Stloc, pc);
        il.Emit(OpCodes.Br, loopHead);

        // Brfalse: if (stack[--sp] == 0) pc = operand;
        il.Append(handlers[VmOp.Brfalse]);
        EmitInc(il, sp, -1);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Brtrue, loopHead);
        il.Emit(OpCodes.Ldloc, operand);
        il.Emit(OpCodes.Stloc, pc);
        il.Emit(OpCodes.Br, loopHead);

        // Ret: return stack[--sp];
        il.Append(handlers[VmOp.Ret]);
        EmitInc(il, sp, -1);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Ret);

        body.OptimizeMacros();
        type.Methods.Add(method);
        return method;
    }

    private static void EmitInc(ILProcessor il, VariableDefinition v, int delta)
    {
        il.Emit(OpCodes.Ldloc, v);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(delta >= 0 ? OpCodes.Add : OpCodes.Sub);
        il.Emit(OpCodes.Stloc, v);
    }

    private static void EmitBinOp(
        ILProcessor il, Instruction label, OpCode op,
        VariableDefinition stack, VariableDefinition sp,
        VariableDefinition lhs, VariableDefinition rhs,
        Instruction loopHead)
    {
        il.Append(label);
        EmitInc(il, sp, -1);
        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Stloc, rhs);

        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Sub);
        il.Emit(OpCodes.Ldelem_I4);
        il.Emit(OpCodes.Stloc, lhs);

        il.Emit(OpCodes.Ldloc, stack);
        il.Emit(OpCodes.Ldloc, sp);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Sub);
        il.Emit(OpCodes.Ldloc, lhs);
        il.Emit(OpCodes.Ldloc, rhs);
        il.Emit(op);
        il.Emit(OpCodes.Stelem_I4);
        il.Emit(OpCodes.Br, loopHead);
    }
}

