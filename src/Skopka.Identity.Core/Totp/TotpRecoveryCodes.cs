using System.Security.Cryptography;
using System.Text;

namespace Skopka.Identity.Totp;

internal static class TotpRecoveryCodes
{
    public static string Create()
    {
        var value = Base32.Encode(RandomNumberGenerator.GetBytes(10));
        return string.Join(
            '-',
            Enumerable.Range(0, 4)
                .Select(index => value.Substring(index * 4, 4)));
    }

    public static string Hash(string value)
    {
        var normalized = Normalize(value);
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));
    }

    private static string Normalize(string value)
        => new(
            value.Where(character => character != '-'
                    && !char.IsWhiteSpace(character))
                .Select(char.ToUpperInvariant)
                .ToArray());

    private static class Base32
    {
        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public static string Encode(ReadOnlySpan<byte> bytes)
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
                    output.Append(Alphabet[(buffer >> bits) & 31]);
                }
            }

            if (bits > 0)
            {
                output.Append(Alphabet[(buffer << (5 - bits)) & 31]);
            }

            return output.ToString();
        }
    }
}
