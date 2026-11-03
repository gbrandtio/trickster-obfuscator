using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;
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

        ApplyDistributed(context, verify, exCtor, excludeType: type);
    }

    /// <summary>
    /// Optional hardening: scatter additional inline whole-image checks across random methods so a
    /// single NOP cannot disable protection, and (when probabilistic response is on) degrade eligible
    /// methods to inert fake returns on tamper instead of throwing at the detection site.
    /// </summary>
    private static void ApplyDistributed(
        DotNetObfuscationContext context, MethodReference verify, MethodReference exCtor,
        TypeDefinition excludeType)
    {
        var opts = context.Config.Features.IntegrityChecks;
        if (opts.DistributedChecks <= 0) return;

        var module = context.Module;
        var gen = context.Names;
        var verifyType = ((MethodDefinition)verify).DeclaringType;
        var excluded = new HashSet<TypeDefinition> { verifyType, excludeType };

        // Shared tamper flag for the silent (probabilistic) response path.
        FieldDefinition? flag = null;
        if (opts.ProbabilisticResponse)
        {
            var monitor = new TypeDefinition(
                string.Empty, gen.Next(),
                TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                    | TypeAttributes.Abstract,
                module.TypeSystem.Object);
            flag = new FieldDefinition(
                gen.Next(), FieldAttributes.Public | FieldAttributes.Static, module.TypeSystem.Boolean);
            monitor.Fields.Add(flag);
            module.Types.Add(monitor);
            excluded.Add(monitor);
        }

        var pool = module.GetTypes()
            .Where(t => !excluded.Contains(t))
            .SelectMany(t => t.Methods)
            .Where(m => CanHostCheck(m, verify))
            .ToList();
        // Fisher-Yates shuffle via the shared entropy source, so placement varies per build.
        for (int i = pool.Count - 1; i > 0; i--)
        {
            int j = context.Entropy.NextInt(i + 1);
            (pool[i], pool[j]) = (pool[j], pool[i]);
        }

        int n = Math.Min(opts.DistributedChecks, pool.Count);
        for (int k = 0; k < n; k++)
            InsertDistributedCheck(pool[k], verify, exCtor, flag);

        if (flag is null)
        {
            context.Logger.Info($"integrity-checks: scattered {n} redundant throwing check(s)");
            return;
        }

        // Probabilistic response: eligible value/string-returning methods divert to an inert fake
        // return once the shared flag has latched, surfacing the failure away from the check site.
        var decoyBytes = new byte[6];
        context.Entropy.NextBytes(decoyBytes);
        var decoy = "svc_" + Convert.ToHexString(decoyBytes).ToLowerInvariant();
        bool keepPublic = context.Config.Features.Rename.KeepPublic;

        int degraded = 0;
        foreach (var method in module.GetTypes()
                     .Where(t => !excluded.Contains(t))
                     .SelectMany(t => t.Methods))
        {
            if (!IsDegradable(method, keepPublic, verify)) continue;
            InsertDegrade(method, flag, decoy);
            degraded++;
        }
        context.Logger.Info(
            $"integrity-checks: scattered {n} check(s); probabilistic degrade on {degraded} method(s)");
    }

    private static bool CanHostCheck(MethodDefinition m, MethodReference verify)
    {
        if (ReferenceEquals(m, verify)) return false;
        if (!m.HasBody || m.Body.Instructions.Count == 0) return false;
        if (m.IsConstructor || m.Name == ".cctor") return false;
        if (m.IsAbstract || m.HasPInvokeInfo) return false;
        if (ReferenceEquals(m.Module.EntryPoint, m)) return false;
        return true;
    }

    private static void InsertDistributedCheck(
        MethodDefinition method, MethodReference verify, MethodReference exCtor, FieldDefinition? flag)
    {
        var body = method.Body;
        body.SimplifyMacros();
        var il = body.GetILProcessor();
        var origFirst = body.Instructions[0];

        var seq = new List<Instruction>
        {
            il.Create(OpCodes.Call, verify),
            il.Create(OpCodes.Brtrue, origFirst), // intact -> real body
        };
        if (flag is null)
        {
            seq.Add(il.Create(OpCodes.Newobj, exCtor));
            seq.Add(il.Create(OpCodes.Throw));
        }
        else
        {
            seq.Add(il.Create(OpCodes.Ldc_I4_1));
            seq.Add(il.Create(OpCodes.Stsfld, flag)); // latch, then fall through to real body
        }
        foreach (var instr in seq)
            il.InsertBefore(origFirst, instr);
        body.OptimizeMacros();
    }

    private static void InsertDegrade(MethodDefinition method, FieldDefinition flag, string decoy)
    {
        var body = method.Body;
        body.SimplifyMacros();
        var il = body.GetILProcessor();
        var origFirst = body.Instructions[0];

        var ret = method.ReturnType;
        var seq = new List<Instruction>
        {
            il.Create(OpCodes.Ldsfld, flag),
            il.Create(OpCodes.Brfalse, origFirst), // not compromised -> real body
        };
        if (ret.MetadataType == MetadataType.String)
        {
            seq.Add(il.Create(OpCodes.Ldstr, decoy));
        }
        else
        {
            var tmp = new VariableDefinition(ret);
            body.Variables.Add(tmp);
            body.InitLocals = true;
            // Long form: OptimizeMacros shrinks to ldloca.s when the index fits, but will not widen an
            // already-short form, so a method with >=255 locals would otherwise truncate the operand.
            seq.Add(il.Create(OpCodes.Ldloca, tmp));
            seq.Add(il.Create(OpCodes.Initobj, ret));
            seq.Add(il.Create(OpCodes.Ldloc, tmp));
        }
        seq.Add(il.Create(OpCodes.Ret));

        foreach (var instr in seq)
            il.InsertBefore(origFirst, instr);
        body.OptimizeMacros();
    }

    // Same safety envelope RASP uses for its fake-return guards: only value/string-returning methods
    // with no by-ref/pointer surface and no state-machine kickoff, honoring keep-public.
    private static bool IsDegradable(MethodDefinition m, bool keepPublic, MethodReference verify)
    {
        if (ReferenceEquals(m, verify)) return false;
        if (!m.HasBody || m.Body.Instructions.Count == 0) return false;
        if (m.IsConstructor || m.IsRuntimeSpecialName) return false;
        if (m.IsGetter || m.IsSetter || m.IsAddOn || m.IsRemoveOn || m.IsFire) return false;
        if (m.IsVirtual || m.IsAbstract || m.HasOverrides) return false;
        if (m.HasPInvokeInfo) return false;
        if (m.DeclaringType.IsInterface) return false;
        if (ReferenceEquals(m.Module.EntryPoint, m)) return false;
        if (HasStateMachineAttribute(m)) return false;
        if (keepPublic && (m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly)) return false;
        foreach (var p in m.Parameters)
            if (p.ParameterType.IsByReference || p.ParameterType.IsPointer) return false;
        var ret = m.ReturnType;
        if (ret.MetadataType == MetadataType.Void) return false;
        if (ret.IsByReference || ret.IsPointer || ret.IsGenericParameter) return false;
        if (ret.MetadataType != MetadataType.String && !ret.IsValueType) return false;
        return true;
    }

    private static bool HasStateMachineAttribute(MethodDefinition m)
    {
        if (!m.HasCustomAttributes) return false;
        foreach (var a in m.CustomAttributes)
        {
            var n = a.AttributeType.FullName;
            if (n == "System.Runtime.CompilerServices.AsyncStateMachineAttribute"
                || n == "System.Runtime.CompilerServices.IteratorStateMachineAttribute")
                return true;
        }
        return false;
    }
}
