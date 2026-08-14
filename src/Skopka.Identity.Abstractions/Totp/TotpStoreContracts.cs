using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Totp;

public enum TotpFactorState
{
    Pending = 0,
    Enabled = 1,
}

public sealed record NewTotpEnrollment(
    Guid UserId,
    Guid EnrollmentId,
    string ProtectedSecret,
    DateTimeOffset ExpiresAt);

public sealed record StoredTotpFactor(
    Guid UserId,
    Guid EnrollmentId,
    string ProtectedSecret,
    TotpFactorState State,
    long? LastAcceptedCounter,
    int RecoveryCodesRemaining,
    long Version,
    DateTimeOffset? PendingExpiresAt,
    DateTimeOffset? EnabledAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset ModifiedAt);

public interface ITotpFactorStore<TProfile>
{
    Task<StoredTotpFactor?> FindByUserIdAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult> CreateOrReplacePendingAsync(
        NewTotpEnrollment enrollment,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<StoredTotpFactor>> EnableAsync(
        Guid userId,
        Guid enrollmentId,
        long expectedVersion,
        long initialAcceptedCounter,
        IReadOnlyCollection<string> recoveryCodeHashes,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult> DisableAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<bool>> TryAcceptCounterAsync(
        Guid userId,
        Guid enrollmentId,
        long expectedVersion,
        long counter,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<bool>> TryConsumeRecoveryCodeAsync(
        Guid userId,
        Guid enrollmentId,
        string recoveryCodeHash,
        DateTimeOffset now,
        CancellationToken ct);
}
