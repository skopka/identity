namespace Skopka.Identity.Verification;

public interface IVerificationCodeKeyProvider
{
    string CurrentKeyId { get; }

    bool TryComputeHmacSha256(
        string keyId,
        ReadOnlySpan<byte> input,
        Span<byte> destination);
}
