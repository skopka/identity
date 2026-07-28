namespace Skopka.Identity.Verification;

internal static class OneTimeCodeVerifierCodec
{
    private const int MaximumVerifierLength = 512;

    public static string Encode(string keyId, ReadOnlySpan<byte> hash)
        => string.Join(
            '$',
            string.Empty,
            "skopka",
            "v=1",
            "otp-hmac-sha256",
            $"kid={keyId}",
            Convert.ToBase64String(hash));

    public static bool TryDecode(
        string verifier,
        out OneTimeCodeVerifier value)
    {
        value = default;

        if (string.IsNullOrEmpty(verifier)
            || verifier.Length > MaximumVerifierLength)
        {
            return false;
        }

        var parts = verifier.Split('$', StringSplitOptions.None);
        if (parts.Length != 6
            || parts[0].Length != 0
            || parts[1] != "skopka"
            || parts[2] != "v=1"
            || parts[3] != "otp-hmac-sha256"
            || !parts[4].StartsWith("kid=", StringComparison.Ordinal)
            || !IsValidKeyId(parts[4].AsSpan(4)))
        {
            return false;
        }

        try
        {
            var hash = Convert.FromBase64String(parts[5]);
            if (hash.Length != 32)
            {
                return false;
            }

            value = new OneTimeCodeVerifier(parts[4][4..], hash);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static bool IsValidKeyId(ReadOnlySpan<char> keyId)
    {
        if (keyId is { Length: < 1 or > 64 })
        {
            return false;
        }

        foreach (var character in keyId)
        {
            if (!char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-')
            {
                return false;
            }
        }

        return true;
    }

    internal readonly record struct OneTimeCodeVerifier(
        string KeyId,
        byte[] Hash);
}
