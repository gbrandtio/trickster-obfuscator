using System.Runtime.Loader;
using System.Text;
using Trickster.Core;
using Trickster.Core.Entropy;
using Trickster.Core.Llm;
using Trickster.DotNet;

namespace Trickster.DotNet.Tests;

/// <summary>Shared helpers: obfuscate the sample library and run its public API by reflection.</summary>
internal static class ObfuscationHarness
{
    public static string SampleDll => typeof(SampleLibrary.Demo).Assembly.Location;

    public static string Obfuscate(TricksterConfig config, string tag)
    {
        var outPath = Path.Combine(
            Path.GetTempPath(), $"trickster-{tag}-{Guid.NewGuid():N}.dll");
        var provider = new OfflineProvider(EntropySource.CreateNonDeterministic());
        AssemblyObfuscator.Obfuscate(SampleDll, outPath, config, provider, NullLogger.Instance);
        return outPath;
    }

    /// <summary>Load an obfuscated assembly in isolation and invoke Demo.Run(n).</summary>
    public static string InvokeRun(string assemblyPath, int n)
    {
        var alc = new AssemblyLoadContext(name: Path.GetFileName(assemblyPath), isCollectible: true);
        try
        {
            var asm = alc.LoadFromAssemblyPath(assemblyPath);
            var type = asm.GetType("SampleLibrary.Demo")
                       ?? throw new Exception("Demo type missing after obfuscation");
            var method = type.GetMethod("Run")
                         ?? throw new Exception("Run method missing after obfuscation");
            return (string)method.Invoke(null, new object[] { n })!;
        }
        finally
        {
            alc.Unload();
        }
    }

    /// <summary>Load an obfuscated assembly in isolation and invoke Demo.ReadPayload().</summary>
    public static string InvokePayload(string assemblyPath)
    {
        var alc = new AssemblyLoadContext(name: Path.GetFileName(assemblyPath), isCollectible: true);
        try
        {
            var asm = alc.LoadFromAssemblyPath(assemblyPath);
            var type = asm.GetType("SampleLibrary.Demo")
                       ?? throw new Exception("Demo type missing after obfuscation");
            var method = type.GetMethod("ReadPayload")
                         ?? throw new Exception("ReadPayload method missing after obfuscation");
            return (string)method.Invoke(null, null)!;
        }
        finally
        {
            alc.Unload();
        }
    }

    // .NET stores IL string literals in the UTF-16 user-string heap, so check both encodings.
    public static bool FileContainsText(string path, string text)
    {
        var bytes = File.ReadAllBytes(path);
        return Contains(bytes, Encoding.Unicode.GetBytes(text))
               || Contains(bytes, Encoding.UTF8.GetBytes(text));
    }

    private static bool Contains(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { match = false; break; }
            if (match) return true;
        }
        return false;
    }

    public static TricksterConfig AllTiersOn()
    {
        var c = TricksterConfig.Default();
        c.Features.Honeypots.Enabled = true;
        c.Features.DecompilerPoison.Enabled = true;
        c.Features.AntiDebug.Enabled = true;
        c.Features.Virtualization.Enabled = true;
        c.Features.Rasp.Enabled = true;
        c.Features.Rasp.AnalysisToolCheck = true;
        c.Features.Rasp.SandboxCheck = true;
        c.Features.LlmBloat.Enabled = true;
        c.Features.LlmBloat.Intensity = "low"; // keep the all-tiers build fast
        c.Features.ResourceEncryption.Enabled = true;
        c.Features.Fingerprint.Enabled = true;
        c.Features.IntegrityChecks.DistributedChecks = 3;
        c.Features.IntegrityChecks.ProbabilisticResponse = true;
        return c;
    }
}
