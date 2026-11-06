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
        NewTotpEnrollment enrollment, DateTimeOffset now, CancellationToken ct);

    /// <summary>Atomically checks and advances the user version while creating the pending factor. The default fails closed.</summary>
    Task<OperationResult> CreateOrReplacePendingAsync(
        NewTotpEnrollment enrollment,
        long expectedUserVersion,
        DateTimeOffset now,
        CancellationToken ct) => Task.FromResult(OperationResultFactory.Fail(
            new Error("identity.concurrency.conflict", "Guarded TOTP enrollment is not supported by this store.", ErrorType.Conflict)));

    Task<OperationResult<StoredTotpFactor>> EnableAsync(Guid userId, Guid enrollmentId,
        long expectedVersion, long initialAcceptedCounter, IReadOnlyCollection<string> recoveryCodeHashes,
        DateTimeOffset now, CancellationToken ct);

    /// <summary>Atomically checks and advances the user version while enabling the exact pending factor. The default fails closed.</summary>
    Task<OperationResult<StoredTotpFactor>> EnableAsync(
        Guid userId,
        Guid enrollmentId,
        long expectedVersion,
        long expectedUserVersion,
        long initialAcceptedCounter,
        IReadOnlyCollection<string> recoveryCodeHashes,
        DateTimeOffset now,
        CancellationToken ct) => Task.FromResult(OperationResultFactory.Fail<StoredTotpFactor>(
            new Error("identity.concurrency.conflict", "Guarded TOTP enrollment is not supported by this store.", ErrorType.Conflict)));

    /// <summary>Atomically checks both versions, removes the exact factor and recovery codes, and rotates the user stamp. The default fails closed.</summary>
    Task<OperationResult> ResetAsync(Guid userId, long expectedUserVersion,
        Guid enrollmentId, long expectedFactorVersion, string newSecurityStamp,
        DateTimeOffset now, CancellationToken ct) => Task.FromResult(OperationResultFactory.Fail(
            new Error("identity.concurrency.conflict", "TOTP reset is not supported by this store.", ErrorType.Conflict)));

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
