using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Trickster.DotNet.Naming;
using Trickster.DotNet.Runtime;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Injects a self-consistency guard that runs from the module initializer: it hashes a baked
/// canary byte array and compares the result to a baked expected digest, throwing on
/// mismatch. An automated tool that rewrites method bodies to strip other tiers tends to
/// perturb this baked data, tripping the check. (v1 scope: self-consistency of the guard,
/// not a whole-file hash; whole-image tamper-proofing is a documented later refinement.)
/// </summary>
public sealed class IntegrityCheckTransform : DotNetTransform
{
    public override string Name => "integrity-checks";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;

        var canary = new byte[48];
        context.Entropy.NextBytes(canary);
        var expected = Convert.ToBase64String(SHA256.HashData(canary));

        var hashData = module.ImportReference(
            typeof(SHA256).GetMethod(nameof(SHA256.HashData), new[] { typeof(byte[]) }));
        var toB64 = module.ImportReference(
            typeof(Convert).GetMethod(nameof(Convert.ToBase64String), new[] { typeof(byte[]) }));
        var strEq = module.ImportReference(
            typeof(string).GetMethod("op_Equality", new[] { typeof(string), typeof(string) }));
        var exCtor = module.ImportReference(
            typeof(InvalidOperationException).GetConstructor(Type.EmptyTypes));

        var type = new TypeDefinition(
            string.Empty, gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var check = new MethodDefinition(
            gen.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.Void);
        var il = check.Body.GetILProcessor();

        // build canary byte[]
        il.Emit(OpCodes.Ldc_I4, canary.Length);
        il.Emit(OpCodes.Newarr, module.TypeSystem.Byte);
        for (int i = 0; i < canary.Length; i++)
        {
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldc_I4, i);
            il.Emit(OpCodes.Ldc_I4, (int)canary[i]);
            il.Emit(OpCodes.Stelem_I1);
        }
        il.Emit(OpCodes.Call, hashData);
        il.Emit(OpCodes.Call, toB64);
        il.Emit(OpCodes.Ldstr, expected);
        il.Emit(OpCodes.Call, strEq);

        var ret = il.Create(OpCodes.Ret);
        il.Emit(OpCodes.Brtrue, ret);
        il.Emit(OpCodes.Newobj, exCtor);
        il.Emit(OpCodes.Throw);
        il.Append(ret);

        type.Methods.Add(check);
        module.Types.Add(type);

        module.GetOrCreateModuleInitializer().PrependCall(check);
        context.Logger.Info("integrity-checks: installed module-initializer guard");
    }
}
