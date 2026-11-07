using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.AccessLinks;

/// <summary>Persisted access link data; only the token hash is stored.</summary>
public sealed record StoredIdentityAccessLink(Guid Id, Guid UserId, long UserVersion, string Scope,
    string TokenHash, DateTimeOffset ExpiresAt, long Version, Guid? EnrollmentId,
    string? ProtectedSecret, DateTimeOffset? EnrollmentExpiresAt, int FailedAttempts, bool Consumed);

/// <summary>Atomic persistence boundary for access-link lifecycle and credential replacement.</summary>
public interface IIdentityAccessLinkStore<TProfile>
{
    Task<StoredIdentityAccessLink?> FindAsync(Guid id, CancellationToken cancellationToken);
    Task<OperationResult> IssueAsync(StoredIdentityAccessLink link, long expectedUserVersion,
        bool invalidateExisting, string newSecurityStamp, DateTimeOffset now, CancellationToken cancellationToken);
    Task<OperationResult> BeginEnrollmentAsync(Guid id, long expectedVersion, Guid enrollmentId,
        string protectedSecret, DateTimeOffset expiresAt, DateTimeOffset now, CancellationToken cancellationToken);
    Task<OperationResult> RecordFailureAsync(Guid id, long expectedVersion, DateTimeOffset now, CancellationToken cancellationToken);
    Task<OperationResult> CompleteAsync(StoredIdentityAccessLink link, string passwordVerifier,
        long acceptedCounter, IReadOnlyCollection<string> recoveryCodeHashes, string newSecurityStamp,
        DateTimeOffset now, CancellationToken cancellationToken);
    Task<int> PruneAsync(DateTimeOffset expiredBefore, int maxCount, CancellationToken cancellationToken);
}
