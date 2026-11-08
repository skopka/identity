using Skopka.Identity.Errors;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;
using Skopka.Identity.Verification;

namespace Skopka.Identity.PhoneOtp;

public sealed record BeginPhoneOtpCommand(string Phone, string? ClientKey = null);

public sealed record VerifyPhoneOtpCommand(
    Guid ChallengeId,
    string Code,
    string? ClientKey = null)
{
    /// <summary>
    /// Trusted, server-selected scope in which the verified phone signs in.
    /// <see langword="null"/> searches the default scope only; accounts holding the same
    /// phone in other scopes are never selected.
    /// </summary>
    public string? PhoneScope { get; init; }
}

/// <summary>Server-authorized target and one-time proof for attaching a confirmed phone.</summary>
/// <remarks>The host must bind the flow to the authenticated user and session.</remarks>
public sealed record BindVerifiedPhoneCommand(
    Guid UserId, long ExpectedVersion, string Phone, VerificationProof Proof)
{
    /// <summary>
    /// Trusted, server-selected scope for the bound phone. <see langword="null"/> keeps the
    /// user's current scope.
    /// </summary>
    public string? PhoneScope { get; init; }
}

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

    /// <summary>Verifies a phone-sign-in code without looking up an account.</summary>
    /// <remarks>Keep the resulting short-lived proof secret and bind it to the authenticated flow.</remarks>
    Task<OperationResult<VerificationProof>> VerifyForBindingAsync(
        VerifyPhoneOtpCommand command, CancellationToken ct)
        => Task.FromResult(OperationResultFactory.Fail<VerificationProof>(new Error(
            IdentityErrorCodes.PhoneBindingUnavailable, "Phone binding is unavailable.", ErrorType.Forbidden)));

    /// <summary>Consumes a verified proof and atomically attaches its confirmed phone.</summary>
    /// <remarks>Requires a server-authorized user and expected version. Custom implementations fail closed by default.</remarks>
    Task<OperationResult<IdentityUser<TProfile>>> BindVerifiedPhoneAsync(
        BindVerifiedPhoneCommand command, CancellationToken ct)
        => Task.FromResult(OperationResultFactory.Fail<IdentityUser<TProfile>>(new Error(
            IdentityErrorCodes.PhoneBindingUnavailable, "Phone binding is unavailable.", ErrorType.Forbidden)));

    Task<OperationResult<VerifiedPhoneOtp<TProfile>>> VerifyAsync(
        VerifyPhoneOtpCommand command,
        CancellationToken ct);
}
