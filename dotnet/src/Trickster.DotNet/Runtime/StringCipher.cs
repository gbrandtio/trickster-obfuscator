using System.Text;

namespace Trickster.DotNet.Runtime;

/// <summary>
/// Build-time string cipher. v1 uses a per-string single-byte XOR so the injected runtime
/// decryptor stays small and provably valid IL. The point of this tier is information
/// removal from the static form (literals become byte arrays + a call), not cryptographic
/// strength; a multi-byte key schedule is a documented later refinement.
/// </summary>
internal static class StringCipher
{
    public static byte[] Encrypt(string value, byte key)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = (byte)(bytes[i] ^ key);
        return bytes;
    }
}
