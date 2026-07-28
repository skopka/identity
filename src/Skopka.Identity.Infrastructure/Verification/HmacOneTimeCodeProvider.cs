using System.Security.Cryptography;
using System.Text;

namespace Skopka.Identity.Verification;

public sealed class HmacOneTimeCodeProvider(
    IVerificationCodeKeyProvider keyProvider,
    HmacOneTimeCodeOptions options)
    : IVerificationMethodProvider
{
    public string Method => VerificationMethods.OneTimeCode;

    public Task<IssuedVerificationMethodChallenge> IssueAsync(
        VerificationMethodContext context,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ValidateOptions(options);

        var maximum = options.Digits switch
        {
            6 => 1_000_000,
            7 => 10_000_000,
            8 => 100_000_000,
            _ => throw new InvalidOperationException(
                "OTP code length is invalid."),
        };
        var code = RandomNumberGenerator
            .GetInt32(maximum)
            .ToString($"D{options.Digits}");
        var input = BuildInput(context, code);
        Span<byte> hash = stackalloc byte[32];
        if (!keyProvider.TryComputeHmacSha256(
                keyProvider.CurrentKeyId,
                input,
                hash))
        {
            throw new InvalidOperationException(
                "The current verification-code key is unavailable.");
        }

        var verifier = OneTimeCodeVerifierCodec.Encode(
            keyProvider.CurrentKeyId,
            hash);
        return Task.FromResult(
            new IssuedVerificationMethodChallenge(verifier, code));
    }

    public Task<bool> VerifyAsync(
        VerificationMethodContext context,
        string verifier,
        string response,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ValidateOptions(options);

        if (!IsValidCode(response, options.Digits)
            || !OneTimeCodeVerifierCodec.TryDecode(verifier, out var decoded))
        {
            return Task.FromResult(false);
        }

        var input = BuildInput(context, response);
        Span<byte> actualHash = stackalloc byte[32];
        if (!keyProvider.TryComputeHmacSha256(
                decoded.KeyId,
                input,
                actualHash))
        {
            return Task.FromResult(false);
        }

        return Task.FromResult(
            CryptographicOperations.FixedTimeEquals(
                actualHash,
                decoded.Hash));
    }

    private static byte[] BuildInput(
        VerificationMethodContext context,
        string code)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(
            stream,
            Encoding.UTF8,
            leaveOpen: true);

        writer.Write(context.ChallengeId.ToByteArray());
        writer.Write(context.UserId.ToByteArray());
        writer.Write(context.Purpose);
        writer.Write(context.Binding);
        writer.Write(code);
        writer.Flush();

        return stream.ToArray();
    }

    private static bool IsValidCode(string response, int digits)
    {
        if (response.Length != digits)
        {
            return false;
        }

        foreach (var character in response)
        {
            if (character is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static void ValidateOptions(HmacOneTimeCodeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Digits is < 6 or > 8)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.Digits),
                "OTP codes must contain between 6 and 8 digits.");
        }
    }
}
