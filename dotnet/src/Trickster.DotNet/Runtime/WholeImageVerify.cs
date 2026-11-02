using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Trickster.DotNet.Transforms;

namespace Trickster.DotNet.Runtime;

/// <summary>
/// Emits a reusable <c>static bool</c> method that verifies the whole-image SHA-256 of the
/// assembly file on disk against the digest stored in the <c>Trickster.Integrity</c> resource.
/// Returns <c>true</c> when the image matches (or cannot be checked, e.g. an in-memory load whose
/// <see cref="System.Reflection.Assembly.Location"/> is empty) and <c>false</c> when it has been
/// tampered with or the integrity resource is missing. The integrity load guard calls it (throwing
/// on <c>false</c>); the RASP monitor calls it periodically (latching its compromised flag).
/// </summary>
internal static class WholeImageVerify
{
    public static MethodDefinition EmitVerifyMethod(
        ModuleDefinition module, string typeName, string methodName)
    {
        var type = new TypeDefinition(
            string.Empty, typeName,
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var method = new MethodDefinition(
            methodName,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.Boolean);

        var hashData = module.ImportReference(
            typeof(SHA256).GetMethod(nameof(SHA256.HashData), new[] { typeof(byte[]) }));
        var toB64Full = module.ImportReference(
            typeof(Convert).GetMethod(nameof(Convert.ToBase64String), new[] { typeof(byte[]) }));
        var toB64Slice = module.ImportReference(
            typeof(Convert).GetMethod(nameof(Convert.ToBase64String), new[] { typeof(byte[]), typeof(int), typeof(int) }));
        var strEq = module.ImportReference(
            typeof(string).GetMethod("op_Equality", new[] { typeof(string), typeof(string) }));
        var isNullOrEmpty = module.ImportReference(
            typeof(string).GetMethod(nameof(string.IsNullOrEmpty), new[] { typeof(string) }));
        var getTypeFromHandle = module.ImportReference(
            typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle), new[] { typeof(RuntimeTypeHandle) }));
        var getAssembly = module.ImportReference(
            typeof(Type).GetProperty(nameof(Type.Assembly))!.GetGetMethod());
        var getLocation = module.ImportReference(
            typeof(System.Reflection.Assembly).GetProperty(nameof(System.Reflection.Assembly.Location))!.GetGetMethod());
        var getResourceStream = module.ImportReference(
            typeof(System.Reflection.Assembly).GetMethod(nameof(System.Reflection.Assembly.GetManifestResourceStream), new[] { typeof(string) }));
        var readAllBytes = module.ImportReference(
            typeof(File).GetMethod(nameof(File.ReadAllBytes), new[] { typeof(string) }));
        var readExactly = module.ImportReference(
            typeof(Stream).GetMethod(nameof(Stream.ReadExactly), new[] { typeof(byte[]), typeof(int), typeof(int) }));
        var toInt32 = module.ImportReference(
            typeof(BitConverter).GetMethod(nameof(BitConverter.ToInt32), new[] { typeof(byte[]), typeof(int) }));
        var arrayClear = module.ImportReference(
            typeof(Array).GetMethod(nameof(Array.Clear), new[] { typeof(Array), typeof(int), typeof(int) }));

        var body = method.Body;
        body.InitLocals = true;
        var byteArrType = new ArrayType(module.TypeSystem.Byte);
        var locAsm = new VariableDefinition(module.ImportReference(typeof(System.Reflection.Assembly)));
        var locPath = new VariableDefinition(module.TypeSystem.String);
        var locFileBytes = new VariableDefinition(byteArrType);
        var locStream = new VariableDefinition(module.ImportReference(typeof(Stream)));
        var locRes = new VariableDefinition(byteArrType);
        var locOffset = new VariableDefinition(module.TypeSystem.Int32);
        var locExpected = new VariableDefinition(module.TypeSystem.String);
        body.Variables.Add(locAsm);
        body.Variables.Add(locPath);
        body.Variables.Add(locFileBytes);
        body.Variables.Add(locStream);
        body.Variables.Add(locRes);
        body.Variables.Add(locOffset);
        body.Variables.Add(locExpected);

        var il = body.GetILProcessor();
        var retTrue = il.Create(OpCodes.Ldc_I4_1);
        var retFalse = il.Create(OpCodes.Ldc_I4_0);
        var ret = il.Create(OpCodes.Ret);

        // asm = typeof(<this type>).Assembly
        il.Emit(OpCodes.Ldtoken, type);
        il.Emit(OpCodes.Call, getTypeFromHandle);
        il.Emit(OpCodes.Callvirt, getAssembly);
        il.Emit(OpCodes.Stloc, locAsm);

        il.Emit(OpCodes.Ldloc, locAsm);
        il.Emit(OpCodes.Callvirt, getLocation);
        il.Emit(OpCodes.Stloc, locPath);

        // if (string.IsNullOrEmpty(path)) return true;  (memory-only load: cannot verify image)
        il.Emit(OpCodes.Ldloc, locPath);
        il.Emit(OpCodes.Call, isNullOrEmpty);
        il.Emit(OpCodes.Brtrue, retTrue);

        il.Emit(OpCodes.Ldloc, locPath);
        il.Emit(OpCodes.Call, readAllBytes);
        il.Emit(OpCodes.Stloc, locFileBytes);

        il.Emit(OpCodes.Ldloc, locAsm);
        il.Emit(OpCodes.Ldstr, IntegrityCheckTransform.ResourceName);
        il.Emit(OpCodes.Callvirt, getResourceStream);
        il.Emit(OpCodes.Stloc, locStream);

        // if (stream == null) return false;  (resource stripped)
        il.Emit(OpCodes.Ldloc, locStream);
        il.Emit(OpCodes.Brfalse, retFalse);

        il.Emit(OpCodes.Ldc_I4, IntegrityCheckTransform.ResourceSize);
        il.Emit(OpCodes.Newarr, module.TypeSystem.Byte);
        il.Emit(OpCodes.Stloc, locRes);

        il.Emit(OpCodes.Ldloc, locStream);
        il.Emit(OpCodes.Ldloc, locRes);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Ldc_I4, IntegrityCheckTransform.ResourceSize);
        il.Emit(OpCodes.Callvirt, readExactly);

        il.Emit(OpCodes.Ldloc, locRes);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Call, toInt32);
        il.Emit(OpCodes.Stloc, locOffset);

        il.Emit(OpCodes.Ldloc, locRes);
        il.Emit(OpCodes.Ldc_I4_4);
        il.Emit(OpCodes.Ldc_I4, 32);
        il.Emit(OpCodes.Call, toB64Slice);
        il.Emit(OpCodes.Stloc, locExpected);

        il.Emit(OpCodes.Ldloc, locFileBytes);
        il.Emit(OpCodes.Ldloc, locOffset);
        il.Emit(OpCodes.Ldc_I4, 32);
        il.Emit(OpCodes.Call, arrayClear);

        // return Base64(SHA256(fileBytes)) == expected;
        il.Emit(OpCodes.Ldloc, locFileBytes);
        il.Emit(OpCodes.Call, hashData);
        il.Emit(OpCodes.Call, toB64Full);
        il.Emit(OpCodes.Ldloc, locExpected);
        il.Emit(OpCodes.Call, strEq);
        il.Emit(OpCodes.Br, ret);

        il.Append(retTrue);
        il.Emit(OpCodes.Br, ret);
        il.Append(retFalse);
        il.Emit(OpCodes.Br, ret);
        il.Append(ret);

        type.Methods.Add(method);
        module.Types.Add(type);
        return method;
    }
}
