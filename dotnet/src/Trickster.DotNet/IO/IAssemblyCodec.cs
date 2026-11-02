using Mono.Cecil;

namespace Trickster.DotNet.IO;

/// <summary>
/// Reads and writes the Cecil assembly model. Isolating I/O from composition lets the engine be
/// tested with an in-memory codec and keeps the orchestrator free of file concerns. Lives in the
/// .NET engine (not Core) because it deals in Cecil's <see cref="AssemblyDefinition"/>.
/// </summary>
public interface IAssemblyCodec
{
    AssemblyDefinition Read(string inputPath);
    void Write(AssemblyDefinition assembly, string outputPath);
}
