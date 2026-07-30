using System.Security.Cryptography;
using System.Text;

namespace Skopka.Identity.RateLimiting;

public sealed class HmacRateLimitPartitionHasher
    : IRateLimitPartitionHasher, IDisposable
{
    private readonly IReadOnlyDictionary<string, byte[]> keys;
    private readonly IReadOnlyCollection<string> versions;
    private bool disposed;

    public HmacRateLimitPartitionHasher(byte[] key)
        : this(
            RateLimitLimits.LegacyPartitionVersion,
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [RateLimitLimits.LegacyPartitionVersion] = key
            })
    {
    }

    public HmacRateLimitPartitionHasher(
        string currentVersion,
        IReadOnlyDictionary<string, byte[]> keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentVersion);
        ArgumentNullException.ThrowIfNull(keys);

        ValidateVersion(currentVersion, nameof(currentVersion));
        if (keys.Count is < 1
            or > RateLimitLimits.MaximumPartitionVersions)
        {
            throw new ArgumentException(
                $"Between 1 and {RateLimitLimits.MaximumPartitionVersions} rate-limit partition keys must be configured.",
                nameof(keys));
        }

        var copiedKeys = new Dictionary<string, byte[]>(
            keys.Count,
            StringComparer.Ordinal);
        try
        {
            foreach (var (version, key) in keys)
            {
                ValidateVersion(version, nameof(keys));
                ArgumentNullException.ThrowIfNull(key);
                if (key.Length < 32)
                {
                    throw new ArgumentException(
                        "Each rate-limit partition key must contain at least 32 bytes.",
                        nameof(keys));
                }

                copiedKeys.Add(version, key.ToArray());
            }

            if (!copiedKeys.ContainsKey(currentVersion))
            {
                throw new ArgumentException(
                    "The current rate-limit partition version is not present in the key collection.",
                    nameof(currentVersion));
            }
        }
        catch
        {
            foreach (var copiedKey in copiedKeys.Values)
            {
                CryptographicOperations.ZeroMemory(copiedKey);
            }

            throw;
        }

        CurrentVersion = currentVersion;
        versions = Array.AsReadOnly<string>(
        [
            currentVersion,
            .. copiedKeys.Keys
                .Where(version => !string.Equals(
                    version,
                    currentVersion,
                    StringComparison.Ordinal))
                .Order(StringComparer.Ordinal),
        ]);
        this.keys = copiedKeys;
    }

    public string CurrentVersion { get; }

    public IReadOnlyCollection<string> Versions => versions;

    public string Hash(
        string version,
        string scope,
        string key)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        if (!keys.TryGetValue(version, out var secret))
        {
            throw new ArgumentException(
                "The requested rate-limit partition version is not configured.",
                nameof(version));
        }

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(
            stream,
            Encoding.UTF8,
            leaveOpen: true);
        writer.Write(scope);
        writer.Write(key);
        writer.Flush();

        return Convert.ToHexString(
            HMACSHA256.HashData(secret, stream.GetBuffer().AsSpan(
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
        foreach (var key in keys.Values)
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void ValidateVersion(
        string version,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(version)
            || version.Length
                > RateLimitLimits.MaximumPartitionVersionLength
            || version.Any(character =>
                !IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-'))
        {
            throw new ArgumentException(
                "Rate-limit partition versions must contain only ASCII letters, digits, '.', '_' or '-'.",
                parameterName);
        }
    }

    private static bool IsAsciiLetterOrDigit(char value)
        => value is >= 'a' and <= 'z'
            or >= 'A' and <= 'Z'
            or >= '0' and <= '9';
}
