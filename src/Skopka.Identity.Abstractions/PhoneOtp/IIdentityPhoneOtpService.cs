using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;
using Skopka.Identity.Verification;

namespace Skopka.Identity.PhoneOtp;

public sealed record BeginPhoneOtpCommand(string Phone, string? ClientKey = null);

public sealed record VerifyPhoneOtpCommand(
    Guid ChallengeId,
    string Code,
    string? ClientKey = null);

public sealed record IssuedPhoneOtpChallenge(
    Guid ChallengeId,
    string Phone,
    DateTimeOffset ExpiresAt,
    TimeSpan RetryAfter,
    string DeliveryCode);

public sealed record VerifiedPhoneOtp<TProfile>(
    string Phone,
    IdentityUser<TProfile>? User,
    VerificationProof? RegistrationProof);

public interface IIdentityPhoneOtpService<TProfile>
{
    Task<OperationResult<IssuedPhoneOtpChallenge>> BeginAsync(
        BeginPhoneOtpCommand command,
        CancellationToken ct);

    Task<OperationResult<VerifiedPhoneOtp<TProfile>>> VerifyAsync(
        VerifyPhoneOtpCommand command,
        CancellationToken ct);
}
