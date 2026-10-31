using System.Security.Cryptography;

namespace Trickster.Core.Entropy;

/// <summary>
/// Source of randomness for every transform. Two modes:
///   * Non-deterministic (default): a CSPRNG seeded from OS entropy. Every build differs
///     and nothing in the (open-source) algorithm lets an attacker reproduce the output.
///   * Deterministic: seeded from a user-supplied secret keyfile, giving reproducible
///     builds whose security rests on the secrecy of that file (Kerckhoffs's principle).
/// The deterministic generator is a SHA-256 counter stream (HKDF-like), not a weak LCG.
/// </summary>
public sealed class EntropySource
{
    private readonly RandomNumberGenerator? _csprng;
    private readonly byte[]? _seed;
    private long _counter;
    private byte[] _block = Array.Empty<byte>();
    private int _blockPos;

    public bool IsDeterministic { get; }

    private EntropySource(RandomNumberGenerator? csprng, byte[]? seed)
    {
        _csprng = csprng;
        _seed = seed;
        IsDeterministic = seed is not null;
    }

    /// <summary>Non-deterministic source backed by the OS CSPRNG.</summary>
    public static EntropySource CreateNonDeterministic()
        => new(RandomNumberGenerator.Create(), null);

    /// <summary>Deterministic source derived from the bytes of a secret seed file.</summary>
    public static EntropySource FromSeedFile(string path)
    {
        var raw = File.ReadAllBytes(path);
        if (raw.Length == 0)
            throw new ArgumentException("Seed file is empty.", nameof(path));
        return FromSeedBytes(raw);
    }

    /// <summary>Deterministic source derived from arbitrary secret bytes.</summary>
    public static EntropySource FromSeedBytes(byte[] raw)
    {
        // Normalize to a fixed-size key so any input works as a seed.
        var seed = SHA256.HashData(raw);
        return new EntropySource(null, seed);
    }

    public void NextBytes(Span<byte> buffer)
    {
        if (_csprng is not null)
        {
            _csprng.GetBytes(buffer);
            return;
        }

        // Deterministic keystream: SHA256(seed || counter) blocks.
        for (int i = 0; i < buffer.Length; i++)
        {
            if (_blockPos >= _block.Length)
            {
                _block = NextKeystreamBlock();
                _blockPos = 0;
            }
            buffer[i] = _block[_blockPos++];
        }
    }

    private byte[] NextKeystreamBlock()
    {
        var input = new byte[_seed!.Length + sizeof(long)];
        Buffer.BlockCopy(_seed, 0, input, 0, _seed.Length);
        BitConverter.GetBytes(_counter++).CopyTo(input, _seed.Length);
        return SHA256.HashData(input);
    }

    /// <summary>Non-negative integer in [0, maxExclusive).</summary>
    public int NextInt(int maxExclusive)
    {
        if (maxExclusive <= 0) throw new ArgumentOutOfRangeException(nameof(maxExclusive));
        Span<byte> b = stackalloc byte[4];
        NextBytes(b);
        uint v = BitConverter.ToUInt32(b);
        return (int)(v % (uint)maxExclusive);
    }

    public int NextInt(int minInclusive, int maxExclusive)
        => minInclusive + NextInt(maxExclusive - minInclusive);

    public bool NextBool() => (NextInt(2) == 1);

    public ulong NextUInt64()
    {
        Span<byte> b = stackalloc byte[8];
        NextBytes(b);
        return BitConverter.ToUInt64(b);
    }

    public T Pick<T>(IReadOnlyList<T> items) => items[NextInt(items.Count)];
}
