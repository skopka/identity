using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Skopka.Identity.Tokens;

public sealed class DataProtectionIdentityActionTokenProvider(
    IDataProtectionProvider dataProtectionProvider)
    : IIdentityActionTokenProvider
{
    private const string RootPurpose = "Skopka.Identity.ActionTokens.v1";
    private const int MaximumTokenLength = 8192;

    public string Generate(IdentityActionTokenPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var protector = CreateProtector(payload.Purpose);
        var serialized = JsonSerializer.SerializeToUtf8Bytes(payload);
        var protectedPayload = protector.Protect(serialized);

        return Convert.ToBase64String(protectedPayload)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public bool TryRead(
        string token,
        IdentityActionTokenPurpose expectedPurpose,
        out IdentityActionTokenPayload? payload)
    {
        payload = null;

        if (string.IsNullOrWhiteSpace(token)
            || token.Length > MaximumTokenLength
            || !TryDecode(token, out var protectedPayload))
        {
            return false;
        }

        try
        {
            var serialized = CreateProtector(expectedPurpose).Unprotect(protectedPayload);
            payload = JsonSerializer.Deserialize<IdentityActionTokenPayload>(serialized);

            return payload is not null
                && payload.Purpose == expectedPurpose;
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private IDataProtector CreateProtector(IdentityActionTokenPurpose purpose)
        => dataProtectionProvider.CreateProtector(
            RootPurpose,
            purpose.ToString());

    private static bool TryDecode(string token, out byte[] value)
    {
        value = [];

        if (token.Length % 4 == 1)
        {
            return false;
        }

        var encoded = token
            .Replace('-', '+')
            .Replace('_', '/');

        encoded = (token.Length % 4) switch
        {
            2 => encoded + "==",
            3 => encoded + "=",
            _ => encoded,
        };

        try
        {
            value = Convert.FromBase64String(encoded);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
