using System.Security.Cryptography;
using System.Text;

namespace Skopka.Identity.Sessions;

public sealed class OpaqueRefreshTokenProvider
    : IIdentityRefreshTokenProvider
{
    private const string FormatPrefix = "v1";
    private const int TokenIdSize = 16;
    private const int SecretSize = 32;

    public GeneratedRefreshToken Generate(Guid tokenId)
    {
        Span<byte> tokenIdBytes = stackalloc byte[TokenIdSize];
        tokenId.TryWriteBytes(tokenIdBytes);

        Span<byte> secret = stackalloc byte[SecretSize];
        RandomNumberGenerator.Fill(secret);

        try
        {
            var token = string.Concat(
                FormatPrefix,
                ".",
                Encode(tokenIdBytes),
                ".",
                Encode(secret));

            return new GeneratedRefreshToken(token, Hash(token));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public bool TryRead(
        string token,
        out Guid tokenId,
        out string? tokenHash)
    {
        tokenId = default;
        tokenHash = null;

        if (string.IsNullOrWhiteSpace(token)
            || token.Length > SessionLimits.MaximumTokenLength)
        {
            return false;
        }

        var parts = token.Split('.');
        if (parts.Length != 3
            || !string.Equals(
                parts[0],
                FormatPrefix,
                StringComparison.Ordinal))
        {
            return false;
        }

        byte[] tokenIdBytes = [];
        byte[] secret = [];
        try
        {
            if (!TryDecode(parts[1], TokenIdSize, out tokenIdBytes)
                || !TryDecode(parts[2], SecretSize, out secret))
            {
                return false;
            }

            tokenId = new Guid(tokenIdBytes);
            tokenHash = Hash(token);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenIdBytes);
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static string Hash(string token)
    {
        var tokenBytes = Encoding.UTF8.GetBytes(token);

        try
        {
            return Convert.ToHexString(SHA256.HashData(tokenBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenBytes);
        }
    }

    private static string Encode(ReadOnlySpan<byte> value)
        => Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static bool TryDecode(
        string value,
        int expectedLength,
        out byte[] decoded)
    {
        decoded = [];

        if (value.Length % 4 == 1)
        {
            return false;
        }

        var encoded = value
            .Replace('-', '+')
            .Replace('_', '/');
        encoded = (value.Length % 4) switch
        {
            2 => encoded + "==",
            3 => encoded + "=",
            _ => encoded,
        };

        try
        {
            decoded = Convert.FromBase64String(encoded);
            return decoded.Length == expectedLength;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
