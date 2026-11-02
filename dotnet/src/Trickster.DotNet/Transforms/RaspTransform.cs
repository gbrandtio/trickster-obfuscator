using System.Runtime.InteropServices;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Runtime Application Self-Protection (RASP). Opt-in, off by default. Injects a self-contained
/// monitor that re-checks for debuggers, profilers, and whole-image tampering DURING execution
/// (not only at load), and guards eligible methods so that, once a check trips, they divert to an
/// inert fake return value instead of running their real body.
/// <para>
/// The monitor's <c>Evaluate()</c> runs on each guarded method entry. Cheap checks (managed +
/// native debugger, profiler env vars) run every call; the whole-image re-hash is throttled to
/// roughly once per <c>integrityIntervalMs</c> (best-effort; the timestamp is not synchronized
/// across threads, so concurrent callers may occasionally re-hash within one window). The first
/// positive check latches a shared
/// <c>Compromised</c> flag. Detection-only: no destructive action, no machine impact, no
/// AV/EDR/sandbox evasion. Native checks are OS-gated and wrapped in try/catch so they never fault
/// an unsupported host (Windows + Linux covered; macOS falls back to the managed + profiler checks).
/// </para>
/// </summary>
public sealed class RaspTransform : DotNetTransform
{
    public override string Name => "rasp";

    public override void Apply(DotNetObfuscationContext context)
    {
        var opts = context.Config.Features.Rasp;
        var module = context.Module;
        var gen = context.Names;

        bool doIntegrity = opts.PeriodicIntegrityCheck && context.WholeImageVerifyMethod is not null;
        if (opts.PeriodicIntegrityCheck && context.WholeImageVerifyMethod is null)
            context.Logger.Warn(
                "rasp: periodic integrity re-check requested but the integrity tier is disabled; " +
                "skipping it (debugger/profiler checks still run)");

        if (!opts.LiveDebuggerCheck && !opts.NativeDebuggerCheck && !opts.ProfilerCheck && !doIntegrity)
        {
            context.Logger.Info("rasp: all checks disabled, nothing to do");
            return;
        }

        // Snapshot eligible targets before injecting the monitor, so RASP never guards its own code.
        // Exclude the shared whole-image verifier: Evaluate() -> CheckIntegrity() -> VerifyImage(),
        // so guarding VerifyImage with an Evaluate() prologue would recurse infinitely.
        bool keepPublic = context.Config.Features.Rename.KeepPublic;
        var verifyMethod = context.WholeImageVerifyMethod;
        var targets = module.GetTypes()
            .SelectMany(t => t.Methods)
            .Where(m => IsEligible(m, keepPublic) && !ReferenceEquals(m, verifyMethod))
            .ToList();

        // Imports.
        var getIsAttached = module.ImportReference(
            typeof(System.Diagnostics.Debugger).GetProperty(nameof(System.Diagnostics.Debugger.IsAttached))!.GetGetMethod());
        var isLogging = module.ImportReference(
            typeof(System.Diagnostics.Debugger).GetMethod(nameof(System.Diagnostics.Debugger.IsLogging)));
        var getEnv = module.ImportReference(
            typeof(Environment).GetMethod(nameof(Environment.GetEnvironmentVariable), new[] { typeof(string) }));
        var tickCount64 = module.ImportReference(
            typeof(Environment).GetProperty(nameof(Environment.TickCount64))!.GetGetMethod());
        var strEq = module.ImportReference(
            typeof(string).GetMethod("op_Equality", new[] { typeof(string), typeof(string) }));
        var isNullOrEmpty = module.ImportReference(
            typeof(string).GetMethod(nameof(string.IsNullOrEmpty), new[] { typeof(string) }));
        var isOSPlatform = module.ImportReference(
            typeof(RuntimeInformation).GetMethod(nameof(RuntimeInformation.IsOSPlatform), new[] { typeof(OSPlatform) }));
        var osWindows = module.ImportReference(
            typeof(OSPlatform).GetProperty(nameof(OSPlatform.Windows))!.GetGetMethod());
        var osLinux = module.ImportReference(
            typeof(OSPlatform).GetProperty(nameof(OSPlatform.Linux))!.GetGetMethod());
        var readAllText = module.ImportReference(
            typeof(File).GetMethod(nameof(File.ReadAllText), new[] { typeof(string) }));
        var regexIsMatch = module.ImportReference(
            typeof(System.Text.RegularExpressions.Regex).GetMethod(
                nameof(System.Text.RegularExpressions.Regex.IsMatch), new[] { typeof(string), typeof(string) }));
        var exceptionType = module.ImportReference(typeof(Exception));

        // Monitor type + shared compromised flag.
        var monitor = new TypeDefinition(
            string.Empty, gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);

        var compromised = new FieldDefinition(
            gen.Next(), FieldAttributes.Public | FieldAttributes.Static, module.TypeSystem.Boolean);
        monitor.Fields.Add(compromised);

        // Native debugger P/Invokes (emitted only when the native check is enabled).
        MethodDefinition? checkNative = null;
        if (opts.NativeDebuggerCheck)
        {
            var kernel32 = new ModuleReference("kernel32.dll");
            module.ModuleReferences.Add(kernel32);

            var isDebuggerPresent = MakePInvoke(kernel32, gen.Next(), "IsDebuggerPresent", module.TypeSystem.Boolean);
            var getCurrentProcess = MakePInvoke(kernel32, gen.Next(), "GetCurrentProcess", module.TypeSystem.IntPtr);
            var checkRemote = MakePInvoke(kernel32, gen.Next(), "CheckRemoteDebuggerPresent",
                module.TypeSystem.Boolean, module.TypeSystem.IntPtr, new ByReferenceType(module.TypeSystem.Boolean));
            monitor.Methods.Add(isDebuggerPresent);
            monitor.Methods.Add(getCurrentProcess);
            monitor.Methods.Add(checkRemote);

            checkNative = BuildCheckNative(module, gen.Next(), exceptionType, isOSPlatform, osWindows,
                osLinux, isDebuggerPresent, getCurrentProcess, checkRemote, readAllText, regexIsMatch);
            monitor.Methods.Add(checkNative);
        }

        MethodDefinition? checkProfiler = null;
        if (opts.ProfilerCheck)
        {
            checkProfiler = BuildCheckProfiler(module, gen.Next(), getEnv, strEq, isNullOrEmpty);
            monitor.Methods.Add(checkProfiler);
        }

        MethodDefinition? checkIntegrity = null;
        if (doIntegrity)
        {
            var nextTicks = new FieldDefinition(
                gen.Next(), FieldAttributes.Public | FieldAttributes.Static, module.TypeSystem.Int64);
            monitor.Fields.Add(nextTicks);
            checkIntegrity = BuildCheckIntegrity(
                module, gen.Next(), tickCount64, nextTicks, context.WholeImageVerifyMethod!,
                opts.IntegrityIntervalMs);
            monitor.Methods.Add(checkIntegrity);
        }

        var evaluate = BuildEvaluate(module, gen.Next(), compromised,
            opts.LiveDebuggerCheck ? getIsAttached : null,
            opts.LiveDebuggerCheck ? isLogging : null,
            checkProfiler, checkNative, checkIntegrity);
        monitor.Methods.Add(evaluate);

        module.Types.Add(monitor);

        // A single inert fake string handed back by string-returning guards. Non-null by design.
        var tokenBytes = new byte[6];
        context.Entropy.NextBytes(tokenBytes);
        var decoyString = "svc_" + Convert.ToHexString(tokenBytes).ToLowerInvariant();

        int guarded = 0;
        foreach (var method in targets)
        {
            GuardMethod(method, evaluate, decoyString);
            guarded++;
        }

        context.Logger.Info($"rasp: installed runtime monitor; guarded {guarded} method(s)");
    }

    private static MethodDefinition MakePInvoke(
        ModuleReference dll, string name, string entryPoint, TypeReference returnType,
        params TypeReference[] parameters)
    {
        var m = new MethodDefinition(
            name,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig
                | MethodAttributes.PInvokeImpl,
            returnType);
        foreach (var p in parameters)
            m.Parameters.Add(new ParameterDefinition(p));
        m.IsPInvokeImpl = true;
        m.IsPreserveSig = true;
        m.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, entryPoint, dll);
        return m;
    }

    private static MethodDefinition BuildCheckProfiler(
        ModuleDefinition module, string name, MethodReference getEnv, MethodReference strEq,
        MethodReference isNullOrEmpty)
    {
        var m = NewBoolMethod(module, name);
        var il = m.Body.GetILProcessor();
        var hit = il.Create(OpCodes.Ldc_I4_1);

        // (CORECLR_ENABLE_PROFILER == "1") || (COR_ENABLE_PROFILING == "1") || !IsNullOrEmpty(CORECLR_PROFILER)
        il.Emit(OpCodes.Ldstr, "CORECLR_ENABLE_PROFILER");
        il.Emit(OpCodes.Call, getEnv);
        il.Emit(OpCodes.Ldstr, "1");
        il.Emit(OpCodes.Call, strEq);
        il.Emit(OpCodes.Brtrue, hit);

        il.Emit(OpCodes.Ldstr, "COR_ENABLE_PROFILING");
        il.Emit(OpCodes.Call, getEnv);
        il.Emit(OpCodes.Ldstr, "1");
        il.Emit(OpCodes.Call, strEq);
        il.Emit(OpCodes.Brtrue, hit);

        il.Emit(OpCodes.Ldstr, "CORECLR_PROFILER");
        il.Emit(OpCodes.Call, getEnv);
        il.Emit(OpCodes.Call, isNullOrEmpty);
        il.Emit(OpCodes.Brfalse, hit);

        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Ret);
        il.Append(hit);
        il.Emit(OpCodes.Ret);
        return m;
    }

    private static MethodDefinition BuildCheckIntegrity(
        ModuleDefinition module, string name, MethodReference tickCount64, FieldDefinition nextTicks,
        MethodReference verify, int intervalMs)
    {
        var m = NewBoolMethod(module, name);
        var body = m.Body;
        body.InitLocals = true;
        var now = new VariableDefinition(module.TypeSystem.Int64);
        body.Variables.Add(now);
        var il = body.GetILProcessor();
        var retFalse = il.Create(OpCodes.Ldc_I4_0);

        il.Emit(OpCodes.Call, tickCount64);
        il.Emit(OpCodes.Stloc, now);

        // if (now < nextTicks) return false;
        il.Emit(OpCodes.Ldloc, now);
        il.Emit(OpCodes.Ldsfld, nextTicks);
        il.Emit(OpCodes.Clt);
        il.Emit(OpCodes.Brtrue, retFalse);

        // nextTicks = now + intervalMs;
        il.Emit(OpCodes.Ldloc, now);
        il.Emit(OpCodes.Ldc_I4, intervalMs);
        il.Emit(OpCodes.Conv_I8);
        il.Emit(OpCodes.Add);
        il.Emit(OpCodes.Stsfld, nextTicks);

        // return !VerifyImage();
        il.Emit(OpCodes.Call, verify);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Ceq);
        il.Emit(OpCodes.Ret);

        il.Append(retFalse);
        il.Emit(OpCodes.Ret);
        return m;
    }

    private static MethodDefinition BuildCheckNative(
        ModuleDefinition module, string name, TypeReference exceptionType,
        MethodReference isOSPlatform, MethodReference osWindows, MethodReference osLinux,
        MethodReference isDebuggerPresent, MethodReference getCurrentProcess, MethodReference checkRemote,
        MethodReference readAllText, MethodReference regexIsMatch)
    {
        var m = NewBoolMethod(module, name);
        var body = m.Body;
        body.InitLocals = true;
        var res = new VariableDefinition(module.TypeSystem.Boolean);
        var flag = new VariableDefinition(module.TypeSystem.Boolean);
        body.Variables.Add(res);
        body.Variables.Add(flag);
        var il = body.GetILProcessor();

        // Branch targets / boundaries created up-front for stable references.
        var tryStart = il.Create(OpCodes.Call, osWindows);       // IsOSPlatform(OSPlatform.Windows)
        var checkRemoteInstr = il.Create(OpCodes.Call, getCurrentProcess);
        var notWin = il.Create(OpCodes.Call, osLinux);           // IsOSPlatform(OSPlatform.Linux)
        var notLinux = il.Create(OpCodes.Nop);                   // placeholder -> leave done
        var catchStart = il.Create(OpCodes.Pop);                 // handler start / try end
        var done = il.Create(OpCodes.Ldloc, res);                // handler end

        // res = false
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Stloc, res);

        // try {
        il.Append(tryStart);                                     // call get_Windows
        il.Emit(OpCodes.Call, isOSPlatform);
        il.Emit(OpCodes.Brfalse, notWin);

        il.Emit(OpCodes.Call, isDebuggerPresent);
        il.Emit(OpCodes.Brfalse, checkRemoteInstr);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Stloc, res);
        il.Emit(OpCodes.Leave, done);

        il.Append(checkRemoteInstr);                             // call GetCurrentProcess
        il.Emit(OpCodes.Ldloca, flag);
        il.Emit(OpCodes.Call, checkRemote);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ldloc, flag);
        il.Emit(OpCodes.Stloc, res);
        il.Emit(OpCodes.Leave, done);

        il.Append(notWin);                                       // call get_Linux
        il.Emit(OpCodes.Call, isOSPlatform);
        il.Emit(OpCodes.Brfalse, notLinux);
        il.Emit(OpCodes.Ldstr, "/proc/self/status");
        il.Emit(OpCodes.Call, readAllText);
        il.Emit(OpCodes.Ldstr, "TracerPid:\\s*[1-9]");
        il.Emit(OpCodes.Call, regexIsMatch);
        il.Emit(OpCodes.Stloc, res);
        il.Emit(OpCodes.Leave, done);

        il.Append(notLinux);                                     // nop
        il.Emit(OpCodes.Leave, done);
        // } catch (Exception) {
        il.Append(catchStart);                                   // pop exception
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Stloc, res);
        il.Emit(OpCodes.Leave, done);
        // }
        il.Append(done);                                         // ldloc res
        il.Emit(OpCodes.Ret);

        body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = catchStart,
            HandlerStart = catchStart,
            HandlerEnd = done,
            CatchType = exceptionType,
        });
        return m;
    }

    private static MethodDefinition BuildEvaluate(
        ModuleDefinition module, string name, FieldDefinition compromised,
        MethodReference? getIsAttached, MethodReference? isLogging,
        MethodReference? checkProfiler, MethodReference? checkNative, MethodReference? checkIntegrity)
    {
        var m = NewBoolMethod(module, name);
        var il = m.Body.GetILProcessor();
        var set = il.Create(OpCodes.Ldc_I4_1);     // latch + return true
        var retTrue = il.Create(OpCodes.Ldc_I4_1); // already compromised

        il.Emit(OpCodes.Ldsfld, compromised);
        il.Emit(OpCodes.Brtrue, retTrue);

        if (getIsAttached is not null)
        {
            il.Emit(OpCodes.Call, getIsAttached);
            il.Emit(OpCodes.Brtrue, set);
        }
        if (isLogging is not null)
        {
            il.Emit(OpCodes.Call, isLogging);
            il.Emit(OpCodes.Brtrue, set);
        }
        if (checkProfiler is not null)
        {
            il.Emit(OpCodes.Call, checkProfiler);
            il.Emit(OpCodes.Brtrue, set);
        }
        if (checkNative is not null)
        {
            il.Emit(OpCodes.Call, checkNative);
            il.Emit(OpCodes.Brtrue, set);
        }
        if (checkIntegrity is not null)
        {
            il.Emit(OpCodes.Call, checkIntegrity);
            il.Emit(OpCodes.Brtrue, set);
        }

        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Ret);

        il.Append(set);                 // ldc.i4.1
        il.Emit(OpCodes.Stsfld, compromised);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Ret);

        il.Append(retTrue);             // ldc.i4.1
        il.Emit(OpCodes.Ret);
        return m;
    }

    private static MethodDefinition NewBoolMethod(ModuleDefinition module, string name)
        => new(name, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            module.TypeSystem.Boolean);

    private static void GuardMethod(
        MethodDefinition method, MethodReference evaluate, string decoyString)
    {
        var body = method.Body;
        var il = body.GetILProcessor();
        body.SimplifyMacros();
        var origFirst = body.Instructions[0];

        var ret = method.ReturnType;
        var seq = new List<Instruction>
        {
            il.Create(OpCodes.Call, evaluate),
            il.Create(OpCodes.Brfalse, origFirst),  // not compromised -> real body
        };

        if (ret.MetadataType == MetadataType.String)
        {
            seq.Add(il.Create(OpCodes.Ldstr, decoyString));   // fake, non-null string
        }
        else
        {
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
        if (ReferenceEquals(m.Module.EntryPoint, m)) return false;
        if (HasStateMachineAttribute(m)) return false;
        if (keepPublic && (m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly)) return false;

        // Exclude by-ref/pointer parameters: the decoy path returns without writing an `out`/`ref`
        // argument, so a caller reading it would see an unwritten value. Leave such methods real.
        foreach (var p in m.Parameters)
            if (p.ParameterType.IsByReference || p.ParameterType.IsPointer) return false;

        var ret = m.ReturnType;
        if (ret.MetadataType == MetadataType.Void) return false;
        if (ret.IsByReference || ret.IsPointer || ret.IsGenericParameter) return false;
        if (ret.MetadataType != MetadataType.String && !ret.IsValueType) return false;
        return true;
    }

    // Matters chiefly for `async ValueTask<T>`/struct-returning async kickoffs, which would otherwise
    // pass the value-type return check; ordinary `async Task`/iterator methods are already excluded by
    // the void-return / reference-return rules. Diverting a state-machine kickoff could hand back a
    // malformed awaitable, so skip them.
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
