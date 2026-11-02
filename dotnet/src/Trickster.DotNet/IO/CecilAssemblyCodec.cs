using Mono.Cecil;

namespace Trickster.DotNet.IO;

/// <summary>Default <see cref="IAssemblyCodec"/> over Mono.Cecil.</summary>
public sealed class CecilAssemblyCodec : IAssemblyCodec
{
    public AssemblyDefinition Read(string inputPath)
    {
        var resolver = new DefaultAssemblyResolver();
        var dir = Path.GetDirectoryName(Path.GetFullPath(inputPath));
        if (!string.IsNullOrEmpty(dir)) resolver.AddSearchDirectory(dir);

        var readParams = new ReaderParameters
        {
            ReadingMode = ReadingMode.Immediate,
            InMemory = true,
            AssemblyResolver = resolver,
        };
        return AssemblyDefinition.ReadAssembly(inputPath, readParams);
    }

    public void Write(AssemblyDefinition assembly, string outputPath) => assembly.Write(outputPath);
}
