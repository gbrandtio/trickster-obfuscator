using System.Text;

namespace Trickster.DotNet.Runtime;

/// <summary>
/// Build-time string cipher using a per-literal multi-byte key and a position-dependent
/// rolling XOR schedule: <c>cipher[i] = plain[i] ^ key[i % key.Length] ^ ((i * 31) &amp; 0xFF)</c>.
/// </summary>
internal static class StringCipher
{
    public const int KeyLength = 8;

    public static byte[] Encrypt(string value, ReadOnlySpan<byte> key)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = (byte)(bytes[i] ^ key[i % key.Length] ^ ((i * 31) & 0xFF));
        return bytes;
    }
}
