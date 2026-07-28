using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Skopka.Identity.Credentials;

public sealed class Argon2idPepperedPasswordHasher : IPasswordHasher
{
    private const int PepperHashSize = 32;

    private readonly IPasswordPepperProvider pepperProvider;
    private readonly int memorySizeKiB;
    private readonly int iterations;
    private readonly int degreeOfParallelism;
    private readonly int saltSize;
    private readonly int hashSize;
    private readonly int maximumAcceptedMemorySizeKiB;
    private readonly int maximumAcceptedIterations;
    private readonly int maximumAcceptedDegreeOfParallelism;

    public Argon2idPepperedPasswordHasher(
        IPasswordPepperProvider pepperProvider,
        Argon2idPepperedPasswordHasherOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(pepperProvider);

        options ??= new Argon2idPepperedPasswordHasherOptions();
        options.Validate();

        if (!PasswordVerifierCodec.IsValidKeyId(pepperProvider.CurrentKeyId))
        {
            throw new ArgumentException(
                "Current pepper key id must contain only ASCII letters, digits, '.', '_' or '-'.",
                nameof(pepperProvider));
        }

        this.pepperProvider = pepperProvider;
        memorySizeKiB = options.MemorySizeKiB;
        iterations = options.Iterations;
        degreeOfParallelism = options.DegreeOfParallelism;
        saltSize = options.SaltSize;
        hashSize = options.HashSize;
        maximumAcceptedMemorySizeKiB = options.MaximumAcceptedMemorySizeKiB;
        maximumAcceptedIterations = options.MaximumAcceptedIterations;
        maximumAcceptedDegreeOfParallelism = options.MaximumAcceptedDegreeOfParallelism;
    }

    public string HashPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var keyId = pepperProvider.CurrentKeyId;
        var pepperedPassword = ComputePepperedPassword(keyId, password);
        if (pepperedPassword is null)
        {
            throw new InvalidOperationException("The current password pepper key is unavailable.");
        }

        var salt = RandomNumberGenerator.GetBytes(saltSize);

        try
        {
            var hash = Derive(
                pepperedPassword,
                salt,
                memorySizeKiB,
                iterations,
                degreeOfParallelism,
                hashSize);

            try
            {
                return PasswordVerifierCodec.EncodeArgon2id(
                    memorySizeKiB,
                    iterations,
                    degreeOfParallelism,
                    keyId,
                    salt,
                    hash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pepperedPassword);
        }
    }

    public PasswordVerificationResult VerifyHashedPassword(
        string passwordVerifier,
        string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(providedPassword);

        if (!PasswordVerifierCodec.TryDecodeArgon2id(passwordVerifier, out var verifier)
            || verifier.MemorySizeKiB > maximumAcceptedMemorySizeKiB
            || verifier.Iterations > maximumAcceptedIterations
            || verifier.DegreeOfParallelism > maximumAcceptedDegreeOfParallelism
            || verifier.MemorySizeKiB < 8L * verifier.DegreeOfParallelism
            || verifier.Salt.Length is < 16 or > 64
            || verifier.Hash.Length is < 32 or > 128)
        {
            return PasswordVerificationResult.Failed;
        }

        var pepperedPassword = ComputePepperedPassword(verifier.KeyId, providedPassword);
        if (pepperedPassword is null)
        {
            return PasswordVerificationResult.Failed;
        }

        try
        {
            var candidate = Derive(
                pepperedPassword,
                verifier.Salt,
                verifier.MemorySizeKiB,
                verifier.Iterations,
                verifier.DegreeOfParallelism,
                verifier.Hash.Length);

            try
            {
                if (!CryptographicOperations.FixedTimeEquals(candidate, verifier.Hash))
                {
                    return PasswordVerificationResult.Failed;
                }

                return verifier.MemorySizeKiB == memorySizeKiB
                    && verifier.Iterations == iterations
                    && verifier.DegreeOfParallelism == degreeOfParallelism
                    && verifier.Salt.Length == saltSize
                    && verifier.Hash.Length == hashSize
                    && verifier.KeyId == pepperProvider.CurrentKeyId
                        ? PasswordVerificationResult.Success
                        : PasswordVerificationResult.SuccessRehashNeeded;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(candidate);
                CryptographicOperations.ZeroMemory(verifier.Hash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pepperedPassword);
        }
    }

    private byte[]? ComputePepperedPassword(string keyId, string password)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var pepperedPassword = new byte[PepperHashSize];

        try
        {
            if (!pepperProvider.TryComputeHmacSha256(
                    keyId,
                    passwordBytes,
                    pepperedPassword))
            {
                CryptographicOperations.ZeroMemory(pepperedPassword);
                return null;
            }

            return pepperedPassword;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] Derive(
        byte[] password,
        byte[] salt,
        int memorySizeKiB,
        int iterations,
        int degreeOfParallelism,
        int outputLength)
    {
        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            MemorySize = memorySizeKiB,
            Iterations = iterations,
            DegreeOfParallelism = degreeOfParallelism
        };

        return argon2.GetBytes(outputLength);
    }
}
