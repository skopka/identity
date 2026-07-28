using System.Security.Cryptography;
using System.Text;

namespace Skopka.Identity.RateLimiting;

public sealed class HmacRateLimitPartitionHasher
    : IRateLimitPartitionHasher, IDisposable
{
    private readonly byte[] key;
    private bool disposed;

    public HmacRateLimitPartitionHasher(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length < 32)
        {
            throw new ArgumentException(
                "The rate-limit partition key must contain at least 32 bytes.",
                nameof(key));
        }

        this.key = key.ToArray();
    }

    public string Hash(string scope, string value)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(
            stream,
            Encoding.UTF8,
            leaveOpen: true);
        writer.Write(scope);
        writer.Write(value);
        writer.Flush();

        return Convert.ToHexString(
            HMACSHA256.HashData(key, stream.GetBuffer().AsSpan(
                0,
                checked((int)stream.Length))));
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        CryptographicOperations.ZeroMemory(key);
    }
}
