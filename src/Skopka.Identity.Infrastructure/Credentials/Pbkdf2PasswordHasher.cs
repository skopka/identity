using System.Security.Cryptography;
using System.Text;

namespace Skopka.Identity.Credentials;

public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    private readonly int iterations;
    private readonly int saltSize;
    private readonly int hashSize;
    private readonly int maximumAcceptedIterations;

    public Pbkdf2PasswordHasher(Pbkdf2PasswordHasherOptions? options = null)
    {
        options ??= new Pbkdf2PasswordHasherOptions();
        options.Validate();

        iterations = options.Iterations;
        saltSize = options.SaltSize;
        hashSize = options.HashSize;
        maximumAcceptedIterations = options.MaximumAcceptedIterations;
    }

    public string HashPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(saltSize);
        var hash = Derive(password, salt, iterations, hashSize);

        try
        {
            return PasswordVerifierCodec.EncodePbkdf2(iterations, salt, hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    public PasswordVerificationResult VerifyHashedPassword(
        string passwordVerifier,
        string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(providedPassword);

        if (!PasswordVerifierCodec.TryDecodePbkdf2(passwordVerifier, out var verifier)
            || verifier.Iterations > maximumAcceptedIterations
            || verifier.Salt.Length is < 16 or > 64
            || verifier.Hash.Length is < 32 or > 128)
        {
            return PasswordVerificationResult.Failed;
        }

        var candidate = Derive(
            providedPassword,
            verifier.Salt,
            verifier.Iterations,
            verifier.Hash.Length);

        try
        {
            if (!CryptographicOperations.FixedTimeEquals(candidate, verifier.Hash))
            {
                return PasswordVerificationResult.Failed;
            }

            return verifier.Iterations == iterations
                && verifier.Salt.Length == saltSize
                && verifier.Hash.Length == hashSize
                    ? PasswordVerificationResult.Success
                    : PasswordVerificationResult.SuccessRehashNeeded;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(candidate);
            CryptographicOperations.ZeroMemory(verifier.Hash);
        }
    }

    private static byte[] Derive(string password, byte[] salt, int iterations, int outputLength)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes,
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                outputLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}
