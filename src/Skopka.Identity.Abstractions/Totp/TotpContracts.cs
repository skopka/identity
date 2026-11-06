using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Totp;

public sealed record BeginTotpEnrollmentCommand(
    Guid UserId,
    string? ClientKey = null);

public sealed record ConfirmTotpEnrollmentCommand(
    Guid UserId,
    Guid EnrollmentId,
    string Code,
    string? ClientKey = null);

/// <summary>Resets the exact enabled factor after the caller has authorized the operation.</summary>
public sealed record ResetTotpCommand(Guid UserId, long ExpectedVersion, Guid ExpectedEnrollmentId);

public sealed record TotpEnrollment(
    Guid EnrollmentId,
    string Secret,
    DateTimeOffset ExpiresAt);

public sealed record TotpFactorStatus(
    Guid UserId,
    bool IsEnabled,
    int RecoveryCodesRemaining,
    DateTimeOffset? EnabledAt)
{
    /// <summary>Identifies the enabled factor for an optimistic reset.</summary>
    public Guid? EnrollmentId { get; init; }
}

public sealed record ConfirmedTotpEnrollment(
    TotpFactorStatus Status,
    IReadOnlyList<string> RecoveryCodes);

public interface IIdentityTotpService<TProfile>
{
    Task<OperationResult<TotpFactorStatus>> GetStatusAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult<TotpEnrollment>> BeginEnrollmentAsync(
        BeginTotpEnrollmentCommand command,
        CancellationToken ct);

    Task<OperationResult<ConfirmedTotpEnrollment>> ConfirmEnrollmentAsync(
        ConfirmTotpEnrollmentCommand command,
        CancellationToken ct);

    /// <summary>Removes the exact enabled factor and rotates the user's security stamp atomically.</summary>
    Task<OperationResult> ResetAsync(ResetTotpCommand command, CancellationToken ct)
        => Task.FromResult(OperationResultFactory.Fail(new Error(
            "identity.concurrency.conflict", "TOTP reset is not supported by this service.", ErrorType.Conflict)));

    Task<OperationResult> DisableAsync(
        Guid userId,
        CancellationToken ct);
}
