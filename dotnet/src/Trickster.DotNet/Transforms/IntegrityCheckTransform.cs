using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Trickster.DotNet.Runtime;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Injects a module-initializer guard that performs two integrity checks at load time:
/// <list type="number">
/// <item><description>A self-consistency check hashing a 48-byte baked canary array against a baked SHA-256 digest (active even for in-memory loads where <see cref="System.Reflection.Assembly.Location"/> is empty).</description></item>
/// <item><description>A whole-image SHA-256 check over the assembly file on disk (zeroing the 32-byte digest slot stored in the <c>Trickster.Integrity</c> embedded resource before hashing, and comparing against the stored 32-byte digest).</description></item>
/// </list>
/// </summary>
public sealed class IntegrityCheckTransform : DotNetTransform
{
    public const string ResourceName = "Trickster.Integrity";
    public const int ResourceSize = 36; // 4-byte slot offset + 32-byte SHA-256 digest

    public override string Name => "integrity-checks";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;

        var canary = new byte[48];
        context.Entropy.NextBytes(canary);
        var expectedCanary = Convert.ToBase64String(SHA256.HashData(canary));

        var marker = new byte[ResourceSize];
        context.Entropy.NextBytes(marker);
        context.Artifacts.Set(ArtifactKeys.WholeImageDigestMarker, marker);
        module.Resources.Add(new EmbeddedResource(
            ResourceName, ManifestResourceAttributes.Private, marker));

        var hashData = module.ImportReference(
            typeof(SHA256).GetMethod(nameof(SHA256.HashData), new[] { typeof(byte[]) }));
        var toB64Full = module.ImportReference(
            typeof(Convert).GetMethod(nameof(Convert.ToBase64String), new[] { typeof(byte[]) }));
        var strEq = module.ImportReference(
            typeof(string).GetMethod("op_Equality", new[] { typeof(string), typeof(string) }));
        var exCtor = module.ImportReference(
            typeof(InvalidOperationException).GetConstructor(Type.EmptyTypes));

        // Shared whole-image verifier (returns false on tamper / missing resource, true when
        // intact or unverifiable). The RASP tier reuses it for its periodic re-check.
        var verify = WholeImageVerify.EmitVerifyMethod(module, gen.Next(), gen.Next());
        context.Artifacts.Set(ArtifactKeys.WholeImageVerifier, verify);

        var type = new TypeDefinition(
            string.Empty, gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var check = new MethodDefinition(
            gen.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.Void);

        var body = check.Body;
        body.InitLocals = true;

        var il = body.GetILProcessor();
        var fail = il.Create(OpCodes.Newobj, exCtor);
        var ret = il.Create(OpCodes.Ret);

        // 1. Self-consistency check on baked 48-byte canary (works for in-memory loads too).
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
        il.Emit(OpCodes.Call, toB64Full);
        il.Emit(OpCodes.Ldstr, expectedCanary);
        il.Emit(OpCodes.Call, strEq);
        il.Emit(OpCodes.Brfalse, fail);

        // 2. Whole-image SHA-256 verification via the shared verifier.
        il.Emit(OpCodes.Call, verify);
        il.Emit(OpCodes.Brtrue, ret);

        il.Append(fail);
        il.Emit(OpCodes.Throw);
        il.Append(ret);

        type.Methods.Add(check);
        module.Types.Add(type);

        module.GetOrCreateModuleInitializer().PrependCall(check);
        context.Logger.Info("integrity-checks: installed canary + whole-image module-initializer guard");
    }
}
