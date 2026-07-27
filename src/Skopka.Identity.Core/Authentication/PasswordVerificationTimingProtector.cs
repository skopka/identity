using System.Security.Cryptography;
using Skopka.Identity.Credentials;

namespace Skopka.Identity.Authentication;

public sealed class PasswordVerificationTimingProtector
    : IPasswordVerificationTimingProtector
{
    private readonly IPasswordHasher passwordHasher;
    private readonly string dummyPasswordVerifier;

    public PasswordVerificationTimingProtector(IPasswordHasher passwordHasher)
    {
        ArgumentNullException.ThrowIfNull(passwordHasher);

        this.passwordHasher = passwordHasher;
        var randomBytes = RandomNumberGenerator.GetBytes(32);

        try
        {
            dummyPasswordVerifier = passwordHasher.HashPassword(
                Convert.ToBase64String(randomBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(randomBytes);
        }
    }

    public void SimulateVerification(string providedPassword)
    {
        _ = passwordHasher.VerifyHashedPassword(
            dummyPasswordVerifier,
            providedPassword);
    }
}
