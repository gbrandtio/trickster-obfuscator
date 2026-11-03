namespace Trickster.DotNet.Runtime;

/// <summary>
/// Symmetric position-rolling XOR over arbitrary bytes, sharing the schedule used by
/// <see cref="StringCipher"/>: <c>out[i] = in[i] ^ key[i % key.Length] ^ ((i * 31) &amp; 0xFF)</c>.
/// Because XOR is involutive the same method both encrypts and decrypts. Used at build time by the
/// resource-encryption and fingerprint tiers; the injected runtime shim and the fingerprint reader
/// reproduce this exact formula.
/// </summary>
internal static class ResourceCipher
{
    public static byte[] Transform(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        var o = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            o[i] = (byte)(data[i] ^ key[i % key.Length] ^ ((i * 31) & 0xFF));
        return o;
    }
}
