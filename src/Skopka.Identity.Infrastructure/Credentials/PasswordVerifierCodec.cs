using System.Globalization;

namespace Skopka.Identity.Credentials;

internal static class PasswordVerifierCodec
{
    private const int MaximumVerifierLength = 2_048;
    private const string Prefix = "skopka";
    private const string Version = "v=1";

    public static string EncodePbkdf2(int iterations, byte[] salt, byte[] hash)
        => string.Join(
            '$',
            string.Empty,
            Prefix,
            Version,
            "pbkdf2-sha256",
            $"i={iterations.ToString(CultureInfo.InvariantCulture)}",
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hash));

    public static bool TryDecodePbkdf2(
        string verifier,
        out Pbkdf2Verifier value)
    {
        value = default;

        if (!TrySplit(verifier, 7, out var parts)
            || parts[3] != "pbkdf2-sha256"
            || !TryReadPositiveInt(parts[4], "i=", out var iterations)
            || !TryReadBase64(parts[5], out var salt)
            || !TryReadBase64(parts[6], out var hash))
        {
            return false;
        }

        value = new Pbkdf2Verifier(iterations, salt, hash);
        return true;
    }

    public static string EncodeArgon2id(
        int memorySizeKiB,
        int iterations,
        int degreeOfParallelism,
        string keyId,
        byte[] salt,
        byte[] hash)
        => string.Join(
            '$',
            string.Empty,
            Prefix,
            Version,
            "argon2id",
            FormattableString.Invariant(
                $"m={memorySizeKiB},t={iterations},p={degreeOfParallelism}"),
            $"kid={keyId}",
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hash));

    public static bool TryDecodeArgon2id(
        string verifier,
        out Argon2idVerifier value)
    {
        value = default;

        if (!TrySplit(verifier, 8, out var parts)
            || parts[3] != "argon2id"
            || !TryReadArgon2Parameters(
                parts[4],
                out var memorySizeKiB,
                out var iterations,
                out var degreeOfParallelism)
            || !parts[5].StartsWith("kid=", StringComparison.Ordinal)
            || !IsValidKeyId(parts[5].AsSpan(4))
            || !TryReadBase64(parts[6], out var salt)
            || !TryReadBase64(parts[7], out var hash))
        {
            return false;
        }

        value = new Argon2idVerifier(
            memorySizeKiB,
            iterations,
            degreeOfParallelism,
            parts[5][4..],
            salt,
            hash);
        return true;
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

    private static bool TrySplit(string verifier, int expectedParts, out string[] parts)
    {
        parts = [];

        if (string.IsNullOrEmpty(verifier) || verifier.Length > MaximumVerifierLength)
        {
            return false;
        }

        parts = verifier.Split('$', StringSplitOptions.None);
        return parts.Length == expectedParts
            && parts[0].Length == 0
            && parts[1] == Prefix
            && parts[2] == Version;
    }

    private static bool TryReadArgon2Parameters(
        string value,
        out int memorySizeKiB,
        out int iterations,
        out int degreeOfParallelism)
    {
        memorySizeKiB = 0;
        iterations = 0;
        degreeOfParallelism = 0;

        var values = value.Split(',', StringSplitOptions.None);
        return values.Length == 3
            && TryReadPositiveInt(values[0], "m=", out memorySizeKiB)
            && TryReadPositiveInt(values[1], "t=", out iterations)
            && TryReadPositiveInt(values[2], "p=", out degreeOfParallelism);
    }

    private static bool TryReadPositiveInt(string value, string prefix, out int result)
    {
        result = 0;
        return value.StartsWith(prefix, StringComparison.Ordinal)
            && int.TryParse(
                value.AsSpan(prefix.Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out result)
            && result > 0;
    }

    private static bool TryReadBase64(string value, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(value);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    internal readonly record struct Pbkdf2Verifier(
        int Iterations,
        byte[] Salt,
        byte[] Hash);

    internal readonly record struct Argon2idVerifier(
        int MemorySizeKiB,
        int Iterations,
        int DegreeOfParallelism,
        string KeyId,
        byte[] Salt,
        byte[] Hash);
}
