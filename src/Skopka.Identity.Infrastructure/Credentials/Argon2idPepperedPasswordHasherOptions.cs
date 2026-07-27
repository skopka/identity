namespace Skopka.Identity.Credentials;

public sealed class Argon2idPepperedPasswordHasherOptions
{
    public int MemorySizeKiB { get; set; } = 65_536;
    public int Iterations { get; set; } = 3;
    public int DegreeOfParallelism { get; set; } = 1;
    public int SaltSize { get; set; } = 16;
    public int HashSize { get; set; } = 32;

    public int MaximumAcceptedMemorySizeKiB { get; set; } = 262_144;
    public int MaximumAcceptedIterations { get; set; } = 6;
    public int MaximumAcceptedDegreeOfParallelism { get; set; } = 4;

    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(DegreeOfParallelism, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            DegreeOfParallelism,
            MaximumAcceptedDegreeOfParallelism);
        ArgumentOutOfRangeException.ThrowIfLessThan(
            (long)MemorySizeKiB,
            8L * DegreeOfParallelism);
        ArgumentOutOfRangeException.ThrowIfLessThan(Iterations, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(SaltSize, 16);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(SaltSize, 64);
        ArgumentOutOfRangeException.ThrowIfLessThan(HashSize, 32);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(HashSize, 128);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaximumAcceptedMemorySizeKiB, MemorySizeKiB);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaximumAcceptedIterations, Iterations);
    }
}
