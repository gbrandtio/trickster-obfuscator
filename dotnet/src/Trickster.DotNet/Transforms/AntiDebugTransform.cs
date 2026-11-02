using System.Diagnostics;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;
using Trickster.DotNet.Naming;
using Trickster.DotNet.Runtime;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Opt-in, off by default. Installs a module-initializer probe that reads
/// <see cref="Debugger.IsAttached"/>.
/// <para>
/// In its default (benign) mode it reads the flag and discards it: no crash, no machine impact,
/// no AV/EDR evasion; it only raises the cost of casual dynamic inspection.
/// </para>
/// <para>
/// When <c>decoy</c> is enabled it degrades to decoy on detection: the probe (sampled once, when
/// the module loads) stores the result in a shared flag, and eligible methods get an entry guard
/// so that, when a debugger was attached at load, they divert into an inert decoy routine and
/// return a provably inert fake value instead of running their real body. To keep the fake value
/// guaranteed non-crashing, only methods returning a value type (diverted to <c>default(T)</c>)
/// or <c>string</c> (diverted to a fake literal) are eligible; reference-returning methods
/// (including <c>Task</c>/async and iterator methods) are left untouched so the decoy can never
/// hand back a <c>null</c> that faults a caller. This is bounded software-protection behavior: it
/// alters only the program's own return values under observation, takes no destructive action,
/// touches no machine state, and performs no sandbox/AV/EDR evasion. With no debugger attached,
/// behavior is identical to the un-obfuscated program.
/// </para>
/// </summary>
public sealed class AntiDebugTransform : DotNetTransform
{
    public override string Name => "anti-debug";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;

        var isAttached = module.ImportReference(
            typeof(Debugger).GetProperty(nameof(Debugger.IsAttached))!.GetGetMethod());

        if (!context.Config.Features.AntiDebug.Decoy)
        {
            InstallBenignProbe(module, gen, isAttached);
            context.Logger.Info("anti-debug: installed benign debugger probe");
            return;
        }

        // Snapshot the methods that already exist, before injecting the holder/decoy members,
        // so the guard is never applied to the members this pass adds.
        bool keepPublic = context.Config.Features.Rename.KeepPublic;
        var targets = module.GetTypes()
            .SelectMany(t => t.Methods)
            .Where(m => IsEligible(m, keepPublic))
            .ToList();

        var holder = new TypeDefinition(
            string.Empty, gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var observed = new FieldDefinition(
            gen.Next(),
            FieldAttributes.Public | FieldAttributes.Static,
            module.TypeSystem.Boolean);
        holder.Fields.Add(observed);

        // Probe: Observed = Debugger.IsAttached; installed at module load.
        var probe = new MethodDefinition(
            gen.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.Void);
        var pil = probe.Body.GetILProcessor();
        pil.Emit(OpCodes.Call, isAttached);
        pil.Emit(OpCodes.Stsfld, observed);
        pil.Emit(OpCodes.Ret);
        holder.Methods.Add(probe);

        // Inert decoy routine the guarded methods divert into when observed. Self-contained and
        // free of side effects; the result is discarded.
        var decoy = new MethodDefinition(
            gen.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.Void);
        var dil = decoy.Body.GetILProcessor();
        int a = context.Entropy.NextInt(3, 100000);
        int b = context.Entropy.NextInt(3, 100000);
        dil.Emit(OpCodes.Ldc_I4, a);
        dil.Emit(OpCodes.Ldc_I4, b);
        dil.Emit(OpCodes.Mul);
        dil.Emit(OpCodes.Ldc_I4, a);
        dil.Emit(OpCodes.Add);
        dil.Emit(OpCodes.Pop);
        dil.Emit(OpCodes.Ret);
        holder.Methods.Add(decoy);

        module.Types.Add(holder);
        module.GetOrCreateModuleInitializer().PrependCall(probe);

        // A single fake string the string-returning guards hand back. Inert and non-null.
        var tokenBytes = new byte[6];
        context.Entropy.NextBytes(tokenBytes);
        var decoyString = "svc_" + Convert.ToHexString(tokenBytes).ToLowerInvariant();

        int guarded = 0;
        foreach (var method in targets)
        {
            GuardMethod(method, observed, decoy, decoyString);
            guarded++;
        }

        context.Logger.Info(
            $"anti-debug: degrade-to-decoy installed; guarded {guarded} method(s)");
    }

    private static void InstallBenignProbe(
        ModuleDefinition module, NameGenerator gen, MethodReference isAttached)
    {
        var type = new TypeDefinition(
            string.Empty, gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var probe = new MethodDefinition(
            gen.Next(),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.Void);
        var il = probe.Body.GetILProcessor();
        il.Emit(OpCodes.Call, isAttached);
        il.Emit(OpCodes.Pop);          // read and discard: benign, within defensive scope
        il.Emit(OpCodes.Ret);

        type.Methods.Add(probe);
        module.Types.Add(type);

        module.GetOrCreateModuleInitializer().PrependCall(probe);
    }

    /// <summary>
    /// Prepends the decoy guard at the method entry, using the SimplifyMacros/InsertBefore pattern
    /// so existing branch targets and try/catch regions stay valid. The divert returns a fake
    /// literal for a <c>string</c> return, otherwise <c>default(T)</c> (a value type); both are
    /// guaranteed non-null, so no caller can be faulted by the decoy path.
    /// </summary>
    private static void GuardMethod(
        MethodDefinition method, FieldDefinition observed, MethodReference decoy, string decoyString)
    {
        var body = method.Body;
        var il = body.GetILProcessor();
        body.SimplifyMacros();
        var origFirst = body.Instructions[0];

        var ret = method.ReturnType;
        var seq = new List<Instruction>
        {
            il.Create(OpCodes.Ldsfld, observed),
            il.Create(OpCodes.Brfalse, origFirst),  // not observed -> real body
            il.Create(OpCodes.Call, decoy),         // observed -> divert to inert decoy
        };

        if (ret.MetadataType == MetadataType.String)
        {
            seq.Add(il.Create(OpCodes.Ldstr, decoyString));   // fake, non-null string
        }
        else
        {
            // Value-type return: zero-init a local and load it (default(T)).
            var tmp = new VariableDefinition(ret);
            body.Variables.Add(tmp);
            body.InitLocals = true;
            seq.Add(il.Create(OpCodes.Ldloca_S, tmp));
            seq.Add(il.Create(OpCodes.Initobj, ret));
            seq.Add(il.Create(OpCodes.Ldloc, tmp));
        }

        seq.Add(il.Create(OpCodes.Ret));

        foreach (var instr in seq)
            il.InsertBefore(origFirst, instr);

        body.OptimizeMacros();
    }

    private static bool IsEligible(MethodDefinition m, bool keepPublic)
    {
        if (!m.HasBody || m.Body.Instructions.Count == 0) return false;
        if (m.IsConstructor || m.IsRuntimeSpecialName) return false;
        if (m.IsGetter || m.IsSetter || m.IsAddOn || m.IsRemoveOn || m.IsFire) return false;
        if (m.IsVirtual || m.IsAbstract || m.HasOverrides) return false;
        if (m.HasPInvokeInfo) return false;
        if (m.DeclaringType.IsInterface) return false;
        if (ReferenceEquals(m.Module.EntryPoint, m)) return false;   // never decoy the entry point
        if (HasStateMachineAttribute(m)) return false;               // async/iterator kickoff methods
        if (keepPublic && (m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly)) return false;

        // Only returns we can divert to a provably inert, non-null value: a value type
        // (default(T)) or string (fake literal). Reference returns (classes, arrays, Task,
        // generic parameters) and by-ref/pointer returns are left untouched so the decoy can
        // never hand a caller a null it would fault on.
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
