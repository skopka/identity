using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Skopka.Identity.Totp;

namespace Skopka.Identity.Infrastructure.Totp;

public sealed class Rfc6238TotpCodeProvider : ITotpCodeProvider
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public string CreateSecret()
        => EncodeBase32(
            RandomNumberGenerator.GetBytes(TotpOptions.StandardSecretSize));

    public bool TryMatchCounter(
        string secret,
        string response,
        DateTimeOffset now,
        long? minimumExclusiveCounter,
        out long counter)
    {
        counter = 0;
        if (response.Length != TotpOptions.StandardDigits
            || response.Any(character => character is < '0' or > '9')
            || !TryDecodeBase32(secret, out var key))
        {
            return false;
        }

        var current = now.ToUnixTimeSeconds()
            / TotpOptions.StandardPeriodSeconds;
        for (var drift = TotpOptions.StandardAllowedTimeStepDrift;
             drift >= -TotpOptions.StandardAllowedTimeStepDrift;
             drift--)
        {
            var candidate = current + drift;
            if (candidate < 0
                || minimumExclusiveCounter is not null
                    && candidate <= minimumExclusiveCounter.Value)
            {
                continue;
            }

            var expected = GenerateCode(key, candidate);
            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected),
                    Encoding.ASCII.GetBytes(response)))
            {
                counter = candidate;
                return true;
            }
        }

        return false;
    }

    private static string GenerateCode(byte[] key, long counter)
    {
        Span<byte> counterBytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);
        var hash = HMACSHA1.HashData(key, counterBytes);
        var offset = hash[^1] & 0x0f;
        var binary = BinaryPrimitives.ReadInt32BigEndian(
                hash.AsSpan(offset, sizeof(int)))
            & 0x7fffffff;
        var code = binary % 1_000_000;
        return code.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string EncodeBase32(ReadOnlySpan<byte> bytes)
    {
        var output = new StringBuilder((bytes.Length * 8 + 4) / 5);
        var buffer = 0;
        var bits = 0;
        foreach (var value in bytes)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                output.Append(Base32Alphabet[(buffer >> bits) & 31]);
            }
        }

        if (bits > 0)
        {
            output.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return output.ToString();
    }

    private static bool TryDecodeBase32(string value, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var output = new List<byte>(value.Length * 5 / 8);
        var buffer = 0;
        var bits = 0;
        foreach (var character in value)
        {
            var index = Base32Alphabet.IndexOf(
                char.ToUpperInvariant(character));
            if (index < 0)
            {
                return false;
            }

            buffer = (buffer << 5) | index;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)(buffer >> bits));
                buffer &= (1 << bits) - 1;
            }
        }

        bytes = output.ToArray();
        return bytes.Length == TotpOptions.StandardSecretSize;
    }
}
