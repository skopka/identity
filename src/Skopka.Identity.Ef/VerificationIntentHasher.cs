using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Skopka.Identity.Ef;

internal static class VerificationIntentHasher
{
    public const int HashLength = 64;

    public static string Hash(
        string purpose,
        string binding,
        string method)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, purpose);
        Append(hash, binding);
        Append(hash, method);
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static void Append(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}
