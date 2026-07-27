namespace Skopka.Identity.Credentials;

public sealed class Pbkdf2PasswordHasherOptions
{
    public int Iterations { get; set; } = 600_000;
    public int SaltSize { get; set; } = 16;
    public int HashSize { get; set; } = 32;
    public int MaximumAcceptedIterations { get; set; } = 2_000_000;

    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(Iterations, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(SaltSize, 16);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(SaltSize, 64);
        ArgumentOutOfRangeException.ThrowIfLessThan(HashSize, 32);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(HashSize, 128);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaximumAcceptedIterations, Iterations);
    }
}
