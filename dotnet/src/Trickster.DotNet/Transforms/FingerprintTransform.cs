using Mono.Cecil;
using Trickster.DotNet.Runtime;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Embeds a per-build fingerprint for leak forensics. The id is derived from the configured customer
/// id plus a build nonce (so it is reproducible under a seed file) and planted across two carriers so
/// stripping one does not remove it: an encrypted private embedded resource (the recoverable channel
/// read by <see cref="FingerprintReader"/>) and an inert constant field. The id is surfaced to the
/// author via the run result. Own-binary only; emits no third-party payload.
/// </summary>
public sealed class FingerprintTransform : DotNetTransform
{
    public const string ResourceName = "Trickster.Fingerprint";

    /// <summary>Marker prefixing every carrier blob so the reader can recognize it. ("TF1")</summary>
    internal static readonly byte[] Magic = { 0x54, 0x46, 0x31 };

    public override string Name => "fingerprint";

    public override void Apply(DotNetObfuscationContext context)
    {
        var module = context.Module;
        var gen = context.Names;

        var nonce = new byte[8];
        context.Entropy.NextBytes(nonce);
        var customer = context.Config.Features.Fingerprint.CustomerId ?? string.Empty;
        var id = (customer.Length > 0 ? customer + ":" : string.Empty)
                 + Convert.ToHexString(nonce).ToLowerInvariant();

        // Blob format: [magic(3)][keyLen(1)][key][cipher], cipher = symmetric XOR (ResourceCipher).
        var key = new byte[8];
        context.Entropy.NextBytes(key);
        var cipher = ResourceCipher.Transform(System.Text.Encoding.UTF8.GetBytes(id), key);
        var blob = new byte[Magic.Length + 1 + key.Length + cipher.Length];
        Buffer.BlockCopy(Magic, 0, blob, 0, Magic.Length);
        blob[Magic.Length] = (byte)key.Length;
        Buffer.BlockCopy(key, 0, blob, Magic.Length + 1, key.Length);
        Buffer.BlockCopy(cipher, 0, blob, Magic.Length + 1 + key.Length, cipher.Length);

        // Carrier 1: encrypted resource (the primary recoverable channel).
        module.Resources.Add(new EmbeddedResource(
            ResourceName, ManifestResourceAttributes.Private, blob));

        // Carrier 2: inert const field holding the same blob (base64); the reader falls back to
        // scanning constants, so stripping the resource alone does not defeat recovery.
        var type = new TypeDefinition(
            string.Empty, gen.Next(),
            TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed
                | TypeAttributes.Abstract,
            module.TypeSystem.Object);
        type.Fields.Add(new FieldDefinition(
            gen.Next(),
            FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal
                | FieldAttributes.HasDefault,
            module.TypeSystem.String)
        { Constant = Convert.ToBase64String(blob) });
        module.Types.Add(type);

        context.Artifacts.Set(ArtifactKeys.Fingerprint, id);
        context.Logger.Info($"fingerprint: embedded build id {id}");
    }
}

/// <summary>
/// Recovers a build fingerprint embedded by <see cref="FingerprintTransform"/> from an assembly file,
/// for leak tracing. Reads the encrypted resource and reverses the symmetric cipher.
/// </summary>
public static class FingerprintReader
{
    /// <summary>Returns the embedded fingerprint, or null if the assembly carries none.</summary>
    public static string? Read(string assemblyPath)
    {
        using var asm = AssemblyDefinition.ReadAssembly(assemblyPath);
        var module = asm.MainModule;

        // Carrier 1: the dedicated resource.
        var res = module.Resources.OfType<EmbeddedResource>()
            .FirstOrDefault(r => r.Name == FingerprintTransform.ResourceName);
        if (res is not null && Decode(res.GetResourceData()) is { } fromResource)
            return fromResource;

        // Carrier 2 (fallback): scan constant string fields for a base64 blob carrying the magic.
        foreach (var type in module.GetTypes())
            foreach (var field in type.Fields)
            {
                if (field.Constant is not string s || s.Length == 0) continue;
                byte[] blob;
                try { blob = Convert.FromBase64String(s); }
                catch (FormatException) { continue; }
                if (Decode(blob) is { } fromConst) return fromConst;
            }
        return null;
    }

    private static string? Decode(byte[] blob)
    {
        var magic = FingerprintTransform.Magic;
        if (blob.Length < magic.Length + 1) return null;
        for (int i = 0; i < magic.Length; i++)
            if (blob[i] != magic[i]) return null;

        int keyLen = blob[magic.Length];
        int keyStart = magic.Length + 1;
        if (keyLen <= 0 || blob.Length < keyStart + keyLen) return null;
        var key = blob.AsSpan(keyStart, keyLen).ToArray();
        var cipher = blob.AsSpan(keyStart + keyLen).ToArray();
        var plain = ResourceCipher.Transform(cipher, key);
        return System.Text.Encoding.UTF8.GetString(plain);
    }
}
