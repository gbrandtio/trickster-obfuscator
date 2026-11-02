using Mono.Cecil;
using Trickster.Core.Artifacts;

namespace Trickster.DotNet;

/// <summary>
/// The .NET engine's catalog of inter-tier artifacts. Each key names a value one tier publishes
/// for another to read, replacing the old mutable fields on the context. Declaring these as the
/// single source of truth lets each tier's module list exactly what it produces/consumes.
/// </summary>
public static class ArtifactKeys
{
    /// <summary>Decoy types injected by misdirection; rename and virtualization skip them.</summary>
    public static readonly ArtifactKey<HashSet<TypeDefinition>> PreservedDecoyTypes = new(nameof(PreservedDecoyTypes));

    /// <summary>The <c>static bool</c> whole-image verifier emitted by integrity; reused by RASP.</summary>
    public static readonly ArtifactKey<MethodDefinition> WholeImageVerifier = new(nameof(WholeImageVerifier));

    /// <summary>The 36-byte integrity resource marker; consumed by the digest post-write step.</summary>
    public static readonly ArtifactKey<byte[]> WholeImageDigestMarker = new(nameof(WholeImageDigestMarker));

    /// <summary>Output: original-name -> obfuscated-name map produced by rename.</summary>
    public static readonly ArtifactKey<Dictionary<string, string>> RenameMap = new(nameof(RenameMap));

    /// <summary>Output: canary identifiers planted by honeypots, surfaced to the caller.</summary>
    public static readonly ArtifactKey<List<string>> Canaries = new(nameof(Canaries));
}
