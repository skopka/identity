using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.Verification;

namespace Skopka.Identity.Ef;

public sealed class EfVerificationChallengeStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IVerificationChallengeStore<TProfile>
{
    private static readonly Error ChallengeInvalidError = new(
        IdentityErrorCodes.VerificationChallengeInvalid,
        "Verification challenge is invalid or expired.",
        ErrorType.Validation);

    private static readonly Error ProofInvalidError = new(
        IdentityErrorCodes.VerificationProofInvalid,
        "Verification proof is invalid or expired.",
        ErrorType.Unauthorized);

    private static readonly Error ConcurrencyError = new(
        IdentityErrorCodes.ConcurrencyConflict,
        "Concurrency conflict.",
        ErrorType.Conflict);

    public Task<StoredVerificationChallenge?> FindByIdAsync(
        Guid challengeId,
        CancellationToken ct)
        => dbContext.VerificationChallenges
            .AsNoTracking()
            .Where(challenge => challenge.Id == challengeId)
            .Select(challenge => Map(challenge))
            .SingleOrDefaultAsync(ct);

    public async Task<OperationResult> CreateAsync(
        NewVerificationChallenge challenge,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var entity = new VerificationChallengeEntity
        {
            Id = challenge.Id,
            UserId = challenge.UserId,
            Purpose = challenge.Purpose,
            Binding = challenge.Binding,
            Method = challenge.Method,
            Verifier = challenge.Verifier,
            SecurityStamp = challenge.SecurityStamp,
            FailedAttemptCount = 0,
            MaxAttempts = challenge.MaxAttempts,
            State = VerificationChallengeState.Pending,
            Version = 1,
            ExpiresAt = challenge.ExpiresAt,
            CreatedAt = now,
            ModifiedAt = now,
        };

        dbContext.VerificationChallenges.Add(entity);
        await dbContext.SaveChangesAsync(ct);
        return OperationResultFactory.Success();
    }

    public async Task<OperationResult<StoredVerificationChallenge>> RecordAttemptAsync(
        Guid challengeId,
        long expectedVersion,
        bool succeeded,
        string? proofHash,
        DateTimeOffset? proofExpiresAt,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (succeeded && (proofHash is null || proofExpiresAt is null))
        {
            throw new ArgumentException(
                "A successful verification attempt requires proof data.");
        }

        var entity = await dbContext.VerificationChallenges
            .SingleOrDefaultAsync(
                challenge => challenge.Id == challengeId,
                ct);

        if (entity is null
            || entity.State != VerificationChallengeState.Pending
            || entity.ExpiresAt <= now
            || entity.FailedAttemptCount >= entity.MaxAttempts)
        {
            Detach(entity);
            return OperationResultFactory.Fail<StoredVerificationChallenge>(
                ChallengeInvalidError);
        }

        if (entity.Version != expectedVersion)
        {
            Detach(entity);
            return OperationResultFactory.Fail<StoredVerificationChallenge>(
                ConcurrencyError);
        }

        if (succeeded)
        {
            entity.State = VerificationChallengeState.Verified;
            entity.ProofHash = proofHash;
            entity.ProofExpiresAt = proofExpiresAt;
            entity.VerifiedAt = now;
        }
        else
        {
            entity.FailedAttemptCount++;
            if (entity.FailedAttemptCount >= entity.MaxAttempts)
            {
                entity.State = VerificationChallengeState.Locked;
            }
        }

        entity.Version = checked(expectedVersion + 1);
        entity.ModifiedAt = now;

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(Map(entity));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(entity);
            return OperationResultFactory.Fail<StoredVerificationChallenge>(
                ConcurrencyError);
        }
    }

    public async Task<OperationResult> ConsumeProofAsync(
        Guid challengeId,
        long expectedVersion,
        Guid userId,
        string purpose,
        string binding,
        string proofHash,
        string securityStamp,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var entity = await dbContext.VerificationChallenges
            .SingleOrDefaultAsync(
                challenge => challenge.Id == challengeId,
                ct);

        if (entity is null
            || entity.State != VerificationChallengeState.Verified
            || entity.ProofExpiresAt is null
            || entity.ProofExpiresAt <= now
            || entity.UserId != userId
            || !string.Equals(entity.Purpose, purpose, StringComparison.Ordinal)
            || !string.Equals(entity.Binding, binding, StringComparison.Ordinal)
            || !string.Equals(
                entity.ProofHash,
                proofHash,
                StringComparison.Ordinal)
            || !string.Equals(
                entity.SecurityStamp,
                securityStamp,
                StringComparison.Ordinal))
        {
            Detach(entity);
            return OperationResultFactory.Fail(ProofInvalidError);
        }

        if (entity.Version != expectedVersion)
        {
            Detach(entity);
            return OperationResultFactory.Fail(ConcurrencyError);
        }

        entity.State = VerificationChallengeState.Consumed;
        entity.ConsumedAt = now;
        entity.ModifiedAt = now;
        entity.Version = checked(expectedVersion + 1);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(entity);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
    }

    private static StoredVerificationChallenge Map(
        VerificationChallengeEntity entity)
        => new(
            entity.Id,
            entity.UserId,
            entity.Purpose,
            entity.Binding,
            entity.Method,
            entity.Verifier,
            entity.SecurityStamp,
            entity.FailedAttemptCount,
            entity.MaxAttempts,
            entity.State,
            entity.ProofHash,
            entity.ProofExpiresAt,
            entity.Version,
            entity.ExpiresAt,
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.VerifiedAt,
            entity.ConsumedAt);

    private void Detach(object? entity)
    {
        if (entity is not null)
        {
            dbContext.Entry(entity).State = EntityState.Detached;
        }
    }
}
