using System.Security.Cryptography;
using Trickster.Core.Artifacts;
using Trickster.Core.IO;

namespace Trickster.DotNet.Transforms;

/// <summary>
/// Post-write step owned by the integrity tier. After the assembly is on disk it finds the
/// integrity resource marker (published as <see cref="ArtifactKeys.WholeImageDigestMarker"/>),
/// records the digest slot offset, zeroes the slot, hashes the whole image, and writes the
/// SHA-256 back into the slot. Keeping this with the integrity tier means the engine never needs
/// to know the marker's layout.
/// </summary>
public sealed class DigestStampStep : IPostWriteStep
{
    public void Apply(string outputPath, IObfuscationArtifacts artifacts)
    {
        if (!artifacts.TryGet(ArtifactKeys.WholeImageDigestMarker, out var marker))
            return;

        var bytes = File.ReadAllBytes(outputPath);
        int pos = bytes.AsSpan().IndexOf(marker);
        if (pos < 0)
            throw new InvalidOperationException("Integrity resource marker not found in written assembly.");

        int digestOffset = pos + 4;
        BitConverter.GetBytes(digestOffset).CopyTo(bytes, pos);
        Array.Clear(bytes, digestOffset, 32);

        var digest = SHA256.HashData(bytes);
        Buffer.BlockCopy(digest, 0, bytes, digestOffset, 32);
        File.WriteAllBytes(outputPath, bytes);
    }
}
