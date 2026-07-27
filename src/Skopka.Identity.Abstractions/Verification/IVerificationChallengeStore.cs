using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Verification;

public interface IVerificationChallengeStore<TProfile>
{
    Task<StoredVerificationChallenge?> FindByIdAsync(
        Guid challengeId,
        CancellationToken ct);

    Task<OperationResult> CreateAsync(
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
