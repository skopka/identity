using System.Security.Cryptography;

namespace Skopka.Identity.Verification;

public sealed class StaticVerificationCodeKeyProvider
    : IVerificationCodeKeyProvider, IDisposable
{
    private readonly IReadOnlyDictionary<string, byte[]> keys;
    private bool disposed;

    public StaticVerificationCodeKeyProvider(
        string currentKeyId,
        byte[] currentKey)
        : this(
            currentKeyId,
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [currentKeyId] = currentKey
            })
    {
    }

    public StaticVerificationCodeKeyProvider(
        string currentKeyId,
        IReadOnlyDictionary<string, byte[]> keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentKeyId);
        ArgumentNullException.ThrowIfNull(keys);

        if (!OneTimeCodeVerifierCodec.IsValidKeyId(currentKeyId))
        {
            throw new ArgumentException(
                "Key id must contain only ASCII letters, digits, '.', '_' or '-'.",
                nameof(currentKeyId));
        }

        foreach (var (keyId, key) in keys)
        {
            if (!OneTimeCodeVerifierCodec.IsValidKeyId(keyId))
            {
                throw new ArgumentException(
                    $"Key id '{keyId}' contains unsupported characters.",
                    nameof(keys));
            }

            ArgumentNullException.ThrowIfNull(key);
            if (key.Length < 32)
            {
                throw new ArgumentException(
                    "Each verification-code key must contain at least 32 bytes.",
                    nameof(keys));
            }
        }

        CurrentKeyId = currentKeyId;
        var copiedKeys = keys.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.ToArray(),
            StringComparer.Ordinal);

        if (!copiedKeys.ContainsKey(currentKeyId))
        {
            foreach (var key in copiedKeys.Values)
            {
                CryptographicOperations.ZeroMemory(key);
            }

            throw new ArgumentException(
                "The current key id is not present in the key collection.",
                nameof(currentKeyId));
        }

        this.keys = copiedKeys;
    }

    public string CurrentKeyId { get; }

    public bool TryComputeHmacSha256(
        string keyId,
        ReadOnlySpan<byte> input,
        Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if (destination.Length < 32)
        {
            throw new ArgumentException(
                "The HMAC-SHA256 destination must contain at least 32 bytes.",
                nameof(destination));
        }

        if (!keys.TryGetValue(keyId, out var key))
        {
            return false;
        }

        HMACSHA256.HashData(key, input, destination);
        return true;
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
}
