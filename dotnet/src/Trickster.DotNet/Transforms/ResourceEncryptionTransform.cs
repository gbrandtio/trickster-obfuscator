using System.Text.RegularExpressions;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Trickster.DotNet.Runtime;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Encrypts the assembly's embedded resources and redirects the author's own
/// <c>Assembly.GetManifestResourceStream(string)</c> calls through an injected shim that transparently
/// decrypts the known-encrypted resources at runtime. This raises the bar against static/offline
/// resource extraction; it is obfuscation, not a cryptographic boundary (the per-build key ships in
/// the assembly). Opt-in, off by default. Runs before the integrity tier, so the integrity resource
/// (and the fingerprint resource) are never encrypted.
/// </summary>
public sealed class ResourceEncryptionTransform : DotNetTransform
{
    public override string Name => "resource-encryption";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;
        var opts = context.Config.Features.ResourceEncryption;

        // Never encrypt Trickster's own resources (fingerprint already added at this point; the
        // integrity resource is added later but excluded defensively).
        var reserved = new HashSet<string>
        {
            FingerprintTransform.ResourceName,
            IntegrityCheckTransform.ResourceName,
        };

        // ResourceManager-backed resx blobs (*.resources) are not read via
        // GetManifestResourceStream(string), so the shim cannot transparently decrypt them; encrypting
        // them would break ResourceManager at runtime. Skip them automatically (with a warning).
        var skippedResx = module.Resources.OfType<EmbeddedResource>()
            .Where(r => !reserved.Contains(r.Name)
                        && !IsExcluded(r.Name, opts.Exclude)
                        && r.Name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Name)
            .ToList();
        if (skippedResx.Count > 0)
            context.Logger.Warn(
                "resource-encryption: skipping ResourceManager resource(s) read outside " +
                "GetManifestResourceStream(string): " + string.Join(", ", skippedResx));

        var targets = module.Resources.OfType<EmbeddedResource>()
            .Where(r => !reserved.Contains(r.Name)
                        && !IsExcluded(r.Name, opts.Exclude)
                        && !r.Name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (targets.Count == 0)
        {
            context.Logger.Info("resource-encryption: no embedded resources to encrypt");
            return;
        }

        // One per-build key for every encrypted resource (random via the shared entropy source).
        var key = new byte[16];
        context.Entropy.NextBytes(key);

        var encryptedNames = new List<string>();
        foreach (var res in targets)
        {
            var plain = res.GetResourceData();
            var cipher = ResourceCipher.Transform(plain, key);
            module.Resources.Remove(res);
            module.Resources.Add(new EmbeddedResource(res.Name, res.Attributes, cipher));
            encryptedNames.Add(res.Name);
        }

        var shim = BuildShim(module, gen, key, encryptedNames);
        int redirected = RedirectCallSites(module, shim);
        context.Logger.Info(
            $"resource-encryption: encrypted {encryptedNames.Count} resource(s); " +
            $"redirected {redirected} lookup call(s)");
    }

    private static bool IsExcluded(string name, List<string> patterns)
    {
        foreach (var p in patterns)
        {
            var rx = "^" + Regex.Escape(p).Replace("\\*", ".*").Replace("\\?", ".") + "$";
            if (Regex.IsMatch(name, rx)) return true;
        }
        return false;
    }

    private static MethodDefinition BuildShim(
        ModuleDefinition module, Naming.NameGenerator gen, byte[] key, List<string> encryptedNames)
    {
        var streamType = module.ImportReference(typeof(Stream));
        var memStreamType = module.ImportReference(typeof(MemoryStream));
        var asmType = module.ImportReference(typeof(System.Reflection.Assembly));
        var byteArray = new ArrayType(module.TypeSystem.Byte);

        var getStream = module.ImportReference(
            typeof(System.Reflection.Assembly).GetMethod(nameof(System.Reflection.Assembly.GetManifestResourceStream), new[] { typeof(string) }));
        var copyTo = module.ImportReference(
            typeof(Stream).GetMethod(nameof(Stream.CopyTo), new[] { typeof(Stream) }));
        var msCtor0 = module.ImportReference(typeof(MemoryStream).GetConstructor(Type.EmptyTypes));
        var msCtorBytes = module.ImportReference(
            typeof(MemoryStream).GetConstructor(new[] { typeof(byte[]) }));
        var toArray = module.ImportReference(
            typeof(MemoryStream).GetMethod(nameof(MemoryStream.ToArray), Type.EmptyTypes));
        var strEq = module.ImportReference(
            typeof(string).GetMethod("op_Equality", new[] { typeof(string), typeof(string) }));

        var type = new TypeDefinition(
            string.Empty, gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var keyField = new FieldDefinition(
            gen.Next(), FieldAttributes.Private | FieldAttributes.Static, byteArray);
        type.Fields.Add(keyField);

        // Static ctor: build the key byte[] inline.
        var cctor = new MethodDefinition(".cctor",
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig
                | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
            module.TypeSystem.Void);
        var cil = cctor.Body.GetILProcessor();
        cil.Emit(OpCodes.Ldc_I4, key.Length);
        cil.Emit(OpCodes.Newarr, module.TypeSystem.Byte);
        for (int i = 0; i < key.Length; i++)
        {
            cil.Emit(OpCodes.Dup);
            cil.Emit(OpCodes.Ldc_I4, i);
            cil.Emit(OpCodes.Ldc_I4, (int)key[i]);
            cil.Emit(OpCodes.Stelem_I1);
        }
        cil.Emit(OpCodes.Stsfld, keyField);
        cil.Emit(OpCodes.Ret);
        type.Methods.Add(cctor);

        // Stream Shim(Assembly asm, string name)
        var shim = new MethodDefinition(
            gen.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            streamType);
        shim.Parameters.Add(new ParameterDefinition(asmType));
        shim.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        var body = shim.Body;
        body.InitLocals = true;
        var s = new VariableDefinition(streamType);      // loc0
        var ms = new VariableDefinition(memStreamType);  // loc1
        var data = new VariableDefinition(byteArray);    // loc2
        var idx = new VariableDefinition(module.TypeSystem.Int32); // loc3
        body.Variables.Add(s); body.Variables.Add(ms); body.Variables.Add(data); body.Variables.Add(idx);
        var il = body.GetILProcessor();

        var returnRaw = il.Create(OpCodes.Ldloc, s);     // return the original stream unchanged
        var doDecrypt = il.Create(OpCodes.Newobj, msCtor0);
        var loop = il.Create(OpCodes.Ldloc, data);
        var test = il.Create(OpCodes.Ldloc, idx);

        // s = asm.GetManifestResourceStream(name)
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Callvirt, getStream);
        il.Emit(OpCodes.Stloc, s);
        // if (s == null) return null;
        il.Emit(OpCodes.Ldloc, s);
        var notNull = il.Create(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Brtrue, notNull);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Ret);
        // name-set check -> doDecrypt, else returnRaw
        il.Append(notNull); // ldarg.1 (first comparison)
        bool first = true;
        foreach (var name in encryptedNames)
        {
            if (!first) il.Emit(OpCodes.Ldarg_1);
            first = false;
            il.Emit(OpCodes.Ldstr, name);
            il.Emit(OpCodes.Call, strEq);
            il.Emit(OpCodes.Brtrue, doDecrypt);
        }
        il.Append(returnRaw); // ldloc s
        il.Emit(OpCodes.Ret);

        // doDecrypt: ms = new MemoryStream(); s.CopyTo(ms); data = ms.ToArray();
        il.Append(doDecrypt); // newobj MemoryStream()
        il.Emit(OpCodes.Stloc, ms);
        il.Emit(OpCodes.Ldloc, s);
        il.Emit(OpCodes.Ldloc, ms);
        il.Emit(OpCodes.Callvirt, copyTo);
        il.Emit(OpCodes.Ldloc, ms);
        il.Emit(OpCodes.Callvirt, toArray);
        il.Emit(OpCodes.Stloc, data);
        // for (i = 0; i < data.Length; i++) data[i] = data[i]^key[i%keyLen]^((i*31)&0xFF)
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Stloc, idx);
        il.Emit(OpCodes.Br, test);
        il.Append(loop); // ldloc data (array for stelem)
        il.Emit(OpCodes.Ldloc, idx);
        il.Emit(OpCodes.Ldloc, data);
        il.Emit(OpCodes.Ldloc, idx);
        il.Emit(OpCodes.Ldelem_U1);
        il.Emit(OpCodes.Ldsfld, keyField);
        il.Emit(OpCodes.Ldloc, idx);
        il.Emit(OpCodes.Ldsfld, keyField);
        il.Emit(OpCodes.Ldlen);
        il.Emit(OpCodes.Conv_I4);
        il.Emit(OpCodes.Rem);
        il.Emit(OpCodes.Ldelem_U1);
        il.Emit(OpCodes.Xor);
        il.Emit(OpCodes.Ldloc, idx);
        il.Emit(OpCodes.Ldc_I4, 31);
        il.Emit(OpCodes.Mul);
        il.Emit(OpCodes.Ldc_I4, 255);
        il.Emit(OpCodes.And);
        il.Emit(OpCodes.Xor);
        il.Emit(OpCodes.Conv_U1);
        il.Emit(OpCodes.Stelem_I1);
        il.Emit(OpCodes.Ldloc, idx);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Add);
        il.Emit(OpCodes.Stloc, idx);
        il.Append(test); // ldloc idx
        il.Emit(OpCodes.Ldloc, data);
        il.Emit(OpCodes.Ldlen);
        il.Emit(OpCodes.Conv_I4);
        il.Emit(OpCodes.Blt, loop);
        // return new MemoryStream(data)
        il.Emit(OpCodes.Ldloc, data);
        il.Emit(OpCodes.Newobj, msCtorBytes);
        il.Emit(OpCodes.Ret);

        type.Methods.Add(shim);
        module.Types.Add(type);
        return shim;
    }

    private static int RedirectCallSites(ModuleDefinition module, MethodDefinition shim)
    {
        int count = 0;
        var shimType = shim.DeclaringType;
        foreach (var type in module.GetTypes())
        {
            if (type == shimType) continue;
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                foreach (var instr in method.Body.Instructions)
                {
                    if (instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt) continue;
                    if (instr.Operand is not MethodReference mr) continue;
                    if (mr.Name != "GetManifestResourceStream") continue;
                    if (mr.DeclaringType.FullName != "System.Reflection.Assembly") continue;
                    if (mr.Parameters.Count != 1
                        || mr.Parameters[0].ParameterType.FullName != "System.String") continue;
                    instr.OpCode = OpCodes.Call;
                    instr.Operand = shim;
                    count++;
                }
            }
        }
        return count;
    }
}
