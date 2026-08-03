using System.Data;
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

    private static readonly Error UserNotFoundError = new(
        IdentityErrorCodes.UserNotFound,
        "User not found.",
        ErrorType.NotFound);

    private const int MaximumSupersedeAttempts = 3;
    private static readonly SemaphoreSlim NonRelationalCreateLock = new(1, 1);

    public Task<StoredVerificationChallenge?> FindByIdAsync(
        Guid challengeId,
        CancellationToken ct)
        => dbContext.VerificationChallenges
            .AsNoTracking()
            .Where(challenge => challenge.Id == challengeId)
            .Select(challenge => Map(challenge))
            .SingleOrDefaultAsync(ct);

    public async Task<OperationResult> CreateAndSupersedeAsync(
        NewVerificationChallenge challenge,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (!dbContext.Database.IsRelational())
        {
            await NonRelationalCreateLock.WaitAsync(ct);
            try
            {
                await SupersedeMatchingChallengesAsync(challenge, now, ct);
                dbContext.VerificationChallenges.Add(
                    CreateEntity(challenge, now));
                await dbContext.SaveChangesAsync(ct);
                return OperationResultFactory.Success();
            }
            finally
            {
                NonRelationalCreateLock.Release();
            }
        }

        if (dbContext.Database.CurrentTransaction is not null)
        {
            return await CreateWithConcurrencyRetriesAsync(
                challenge,
                now,
                ownsTransaction: false,
                ct);
        }

        var strategy = dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(
            async cancellationToken =>
            {
                try
                {
                    return await CreateWithConcurrencyRetriesAsync(
                        challenge,
                        now,
                        ownsTransaction: true,
                        cancellationToken);
                }
                catch
                {
                    DetachChallengeEntries();
                    throw;
                }
            },
            ct);
    }

    private async Task<OperationResult> CreateWithConcurrencyRetriesAsync(
        NewVerificationChallenge challenge,
        DateTimeOffset now,
        bool ownsTransaction,
        CancellationToken ct)
    {
        for (var attempt = 1; attempt <= MaximumSupersedeAttempts; attempt++)
        {
            try
            {
                if (!ownsTransaction)
                {
                    return await CreateWithinRelationalTransactionAsync(
                        challenge,
                        now,
                        ct);
                }

                await using var transaction = await dbContext.Database
                    .BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
                var result = await CreateWithinRelationalTransactionAsync(
                    challenge,
                    now,
                    ct);
                if (!result.IsSuccess)
                {
                    return result;
                }

                await transaction.CommitAsync(ct);
                return result;
            }
            catch (DbUpdateConcurrencyException)
            {
                DetachChallengeEntries();
                if (attempt == MaximumSupersedeAttempts)
                {
                    return OperationResultFactory.Fail(ConcurrencyError);
                }
            }
        }

        throw new InvalidOperationException("Unreachable verification store state.");
    }

    private async Task<OperationResult> CreateWithinRelationalTransactionAsync(
        NewVerificationChallenge challenge,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var userExists = await dbContext.Users
            .Where(user => user.Id == challenge.UserId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    user => user.ModifiedAt,
                    user => user.ModifiedAt),
                ct);
        if (userExists == 0)
        {
            return OperationResultFactory.Fail(UserNotFoundError);
        }

        var existing = await dbContext.VerificationChallenges
            .AsNoTracking()
            .SingleOrDefaultAsync(
                entity => entity.Id == challenge.Id,
                ct);
        if (existing is not null)
        {
            return IsSamePendingChallenge(existing, challenge, now)
                ? OperationResultFactory.Success()
                : OperationResultFactory.Fail(ConcurrencyError);
        }

        var superseded = await SupersedeMatchingChallengesAsync(
            challenge,
            now,
            ct);
        if (superseded)
        {
            await dbContext.SaveChangesAsync(ct);
        }

        dbContext.VerificationChallenges.Add(CreateEntity(challenge, now));
        await dbContext.SaveChangesAsync(ct);
        return OperationResultFactory.Success();
    }

    private static bool IsSamePendingChallenge(
        VerificationChallengeEntity existing,
        NewVerificationChallenge challenge,
        DateTimeOffset now)
        => existing.State == VerificationChallengeState.Pending
            && existing.ExpiresAt > now
            && existing.UserId == challenge.UserId
            && string.Equals(
                existing.Purpose,
                challenge.Purpose,
                StringComparison.Ordinal)
            && string.Equals(
                existing.Binding,
                challenge.Binding,
                StringComparison.Ordinal)
            && string.Equals(
                existing.Method,
                challenge.Method,
                StringComparison.Ordinal)
            && string.Equals(
                existing.Verifier,
                challenge.Verifier,
                StringComparison.Ordinal)
            && string.Equals(
                existing.SecurityStamp,
                challenge.SecurityStamp,
                StringComparison.Ordinal)
            && existing.MaxAttempts == challenge.MaxAttempts
            && existing.ExpiresAt
                == NormalizeStoreTimestamp(challenge.ExpiresAt);

    private async Task<bool> SupersedeMatchingChallengesAsync(
        NewVerificationChallenge challenge,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var activeChallenges = await dbContext.VerificationChallenges
            .Where(entity => entity.UserId == challenge.UserId
                && entity.Purpose == challenge.Purpose
                && entity.Binding == challenge.Binding
                && entity.Method == challenge.Method
                && (entity.State == VerificationChallengeState.Pending
                    || entity.State == VerificationChallengeState.Verified))
            .ToListAsync(ct);

        foreach (var activeChallenge in activeChallenges)
        {
            activeChallenge.State = VerificationChallengeState.Superseded;
            activeChallenge.Version = checked(activeChallenge.Version + 1);
            activeChallenge.ModifiedAt = now;
        }

        return activeChallenges.Count > 0;
    }

    private static VerificationChallengeEntity CreateEntity(
        NewVerificationChallenge challenge,
        DateTimeOffset now)
        => new()
        {
            Id = challenge.Id,
            UserId = challenge.UserId,
            IntentHash = VerificationIntentHasher.Hash(
                challenge.Purpose,
                challenge.Binding,
                challenge.Method),
            Purpose = challenge.Purpose,
            Binding = challenge.Binding,
            Method = challenge.Method,
            Verifier = challenge.Verifier,
            SecurityStamp = challenge.SecurityStamp,
            FailedAttemptCount = 0,
            MaxAttempts = challenge.MaxAttempts,
            State = VerificationChallengeState.Pending,
            Version = 1,
            ExpiresAt = NormalizeStoreTimestamp(challenge.ExpiresAt),
            CreatedAt = now,
            ModifiedAt = now,
        };

    private static DateTimeOffset NormalizeStoreTimestamp(
        DateTimeOffset value)
    {
        const long ticksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(
            utc.Ticks - (utc.Ticks % ticksPerMicrosecond),
            TimeSpan.Zero);
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

    private void DetachChallengeEntries()
    {
        foreach (var entry in dbContext.ChangeTracker
            .Entries<VerificationChallengeEntity>()
            .ToArray())
        {
            entry.State = EntityState.Detached;
        }
    }
}
