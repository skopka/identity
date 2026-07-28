namespace Skopka.Identity.Credentials;

public interface IPasswordPepperProvider
{
    string CurrentKeyId { get; }

    bool TryComputeHmacSha256(
        string keyId,
        ReadOnlySpan<byte> input,
        Span<byte> destination);
}
