using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Verification;

public interface IVerificationChallengeStore<TProfile>
{
    Task<StoredVerificationChallenge?> FindByIdAsync(
        Guid challengeId,
        CancellationToken ct);

    /// <summary>
    /// Atomically creates a pending challenge and supersedes every active challenge
    /// for the same verification intent.
    /// </summary>
    /// <remarks>
    /// An intent is the exact ordinal tuple of user id, purpose, binding and method.
    /// Pending and verified challenges are active even after their expiry timestamp;
    /// each must transition to <see cref="VerificationChallengeState.Superseded"/>
    /// with an incremented version and updated modification time in the same atomic
    /// operation that creates the new pending challenge. Concurrent calls for one
    /// intent use latest-write-wins semantics and must leave at most one active row.
    /// Challenges for different intents remain independent and may coexist.
    /// </remarks>
    Task<OperationResult> CreateAndSupersedeAsync(
        NewVerificationChallenge challenge,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<StoredVerificationChallenge>> RecordAttemptAsync(
        Guid challengeId,
        long expectedVersion,
        bool succeeded,
        string? proofHash,
        DateTimeOffset? proofExpiresAt,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult> ConsumeProofAsync(
        Guid challengeId,
        long expectedVersion,
        Guid userId,
        string purpose,
        string binding,
        string proofHash,
        string securityStamp,
        DateTimeOffset now,
        CancellationToken ct);
}
