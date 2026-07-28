using System.Security.Cryptography;
using System.Text;

namespace Skopka.Identity.Verification;

internal static class VerificationProofCodec
{
    public static string Generate()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public static string Hash(string proof)
        => Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(proof)));

    public static bool Matches(string expectedHash, string proof)
    {
        var actualHash = Hash(proof);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expectedHash),
            Encoding.ASCII.GetBytes(actualHash));
    }
}
