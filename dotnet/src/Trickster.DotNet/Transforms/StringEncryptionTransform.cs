using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;
using Trickster.DotNet.Naming;
using Trickster.DotNet.Runtime;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Replaces every string literal (`ldstr`) with a call to an injected decryptor over an
/// encrypted byte array. The plaintext is absent from the static form, so a static analyzer
/// sees ciphertext + a call rather than the string (information removal, Tier 3).
/// </summary>
public sealed class StringEncryptionTransform : DotNetTransform
{
    public override string Name => "string-encryption";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var nameGen = context.Names;

        var decryptor = BuildDecryptor(module, nameGen.Next(), nameGen.Next());
        module.Types.Add(decryptor.DeclaringType);

        int rewritten = 0;
        foreach (var type in module.GetTypes())
        {
            if (type == decryptor.DeclaringType) continue;
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                rewritten += RewriteMethod(module, method, decryptor, context.Entropy);
            }
        }
        context.Logger.Info($"string-encryption: rewrote {rewritten} literal(s)");
    }

    private static int RewriteMethod(
        ModuleDefinition module, MethodDefinition method, MethodReference decryptor,
        Core.Entropy.EntropySource entropy)
    {
        var sites = method.Body.Instructions
            .Where(i => i.OpCode == OpCodes.Ldstr && i.Operand is string s && s.Length > 0)
            .ToList();
        if (sites.Count == 0) return 0; // leave literal-free bodies untouched

        var il = method.Body.GetILProcessor();
        method.Body.SimplifyMacros();  // long-form branches so inserts can't overflow br.s

        foreach (var ldstr in sites)
        {
            var text = (string)ldstr.Operand;
            var key = new byte[StringCipher.KeyLength];
            for (int k = 0; k < key.Length; k++)
                key[k] = (byte)entropy.NextInt(1, 256);
            var cipher = StringCipher.Encrypt(text, key);

            // Mutate the ldstr IN PLACE into the first replacement instruction so that any
            // branch targeting it stays valid, then append the rest after it. (il.Replace
            // does not redirect branches that pointed at the old instruction.)
            ldstr.OpCode = OpCodes.Ldc_I4;
            ldstr.Operand = cipher.Length;

            var tail = new List<Instruction> { il.Create(OpCodes.Newarr, module.TypeSystem.Byte) };
            for (int i = 0; i < cipher.Length; i++)
            {
                tail.Add(il.Create(OpCodes.Dup));
                tail.Add(il.Create(OpCodes.Ldc_I4, i));
                tail.Add(il.Create(OpCodes.Ldc_I4, (int)cipher[i]));
                tail.Add(il.Create(OpCodes.Stelem_I1));
            }
            tail.Add(il.Create(OpCodes.Ldc_I4, key.Length));
            tail.Add(il.Create(OpCodes.Newarr, module.TypeSystem.Byte));
            for (int k = 0; k < key.Length; k++)
            {
                tail.Add(il.Create(OpCodes.Dup));
                tail.Add(il.Create(OpCodes.Ldc_I4, k));
                tail.Add(il.Create(OpCodes.Ldc_I4, (int)key[k]));
                tail.Add(il.Create(OpCodes.Stelem_I1));
            }
            tail.Add(il.Create(OpCodes.Call, decryptor));

            var anchor = ldstr;
            foreach (var instr in tail)
            {
                il.InsertAfter(anchor, instr);
                anchor = instr;
            }
        }
        if (sites.Count > 0) method.Body.OptimizeMacros();
        return sites.Count;
    }

    private static MethodDefinition BuildDecryptor(
        ModuleDefinition module, string typeName, string methodName)
    {
        var type = new TypeDefinition(
            string.Empty, typeName,
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract, // static class
            module.TypeSystem.Object);

        var method = new MethodDefinition(
            methodName,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.String);
        method.Parameters.Add(new ParameterDefinition(
            new ArrayType(module.TypeSystem.Byte)));
        method.Parameters.Add(new ParameterDefinition(
            new ArrayType(module.TypeSystem.Byte)));

        var getUtf8 = module.ImportReference(
            typeof(Encoding).GetProperty(nameof(Encoding.UTF8))!.GetGetMethod());
        var getString = module.ImportReference(
            typeof(Encoding).GetMethod(nameof(Encoding.GetString), new[] { typeof(byte[]) }));

        var body = method.Body = new MethodBody(method);
        body.InitLocals = true;
        var i = new VariableDefinition(module.TypeSystem.Int32);
        body.Variables.Add(i);
        var il = body.GetILProcessor();

        var loop = il.Create(OpCodes.Ldarg_0);
        var test = il.Create(OpCodes.Ldloc, i);

        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Stloc, i);
        il.Emit(OpCodes.Br, test);

        // data[i] = (byte)(data[i] ^ key[i % key.Length] ^ ((i * 31) & 0xFF))
        il.Append(loop);                 // ldarg.0 (data, for stelem)
        il.Emit(OpCodes.Ldloc, i);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldloc, i);
        il.Emit(OpCodes.Ldelem_U1);
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Ldloc, i);
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Ldlen);
        il.Emit(OpCodes.Conv_I4);
        il.Emit(OpCodes.Rem);
        il.Emit(OpCodes.Ldelem_U1);
        il.Emit(OpCodes.Xor);
        il.Emit(OpCodes.Ldloc, i);
        il.Emit(OpCodes.Ldc_I4, 31);
        il.Emit(OpCodes.Mul);
        il.Emit(OpCodes.Ldc_I4, 255);
        il.Emit(OpCodes.And);
        il.Emit(OpCodes.Xor);
        il.Emit(OpCodes.Conv_U1);
        il.Emit(OpCodes.Stelem_I1);
        il.Emit(OpCodes.Ldloc, i);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Add);
        il.Emit(OpCodes.Stloc, i);

        il.Append(test);                 // ldloc i
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldlen);
        il.Emit(OpCodes.Conv_I4);
        il.Emit(OpCodes.Blt, loop);

        il.Emit(OpCodes.Call, getUtf8);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Callvirt, getString);
        il.Emit(OpCodes.Ret);

        type.Methods.Add(method);
        return method;
    }
}
