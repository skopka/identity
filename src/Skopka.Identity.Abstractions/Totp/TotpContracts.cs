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

public sealed record TotpEnrollment(
    Guid EnrollmentId,
    string Secret,
    DateTimeOffset ExpiresAt);

public sealed record TotpFactorStatus(
    Guid UserId,
    bool IsEnabled,
    int RecoveryCodesRemaining,
    DateTimeOffset? EnabledAt);

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

    Task<OperationResult> DisableAsync(
        Guid userId,
        CancellationToken ct);
}
