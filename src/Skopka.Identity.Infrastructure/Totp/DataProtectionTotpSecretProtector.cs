using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Skopka.Identity.Totp;

namespace Skopka.Identity.Infrastructure.Totp;

public sealed class DataProtectionTotpSecretProtector(
    IDataProtectionProvider provider)
    : ITotpSecretProtector
{
    private readonly IDataProtector protector = provider.CreateProtector(
        "Skopka.Identity.Totp.Secret",
        "v1");

    public string Protect(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        return protector.Protect(secret);
    }

    public bool TryUnprotect(string protectedSecret, out string secret)
    {
        secret = string.Empty;
        if (string.IsNullOrWhiteSpace(protectedSecret))
        {
            return false;
        }

        try
        {
            secret = protector.Unprotect(protectedSecret);
            return !string.IsNullOrWhiteSpace(secret);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
