using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.Sessions;

namespace Skopka.Identity.Ef;

public sealed class EfIdentityRefreshSessionStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IIdentityRefreshSessionStore<TProfile>
{
    private const int MaximumConcurrencyRetries = 3;

    private static readonly Error RefreshTokenInvalidError = new(
        IdentityErrorCodes.RefreshTokenInvalid,
        "The refresh token is invalid or expired.",
        ErrorType.Unauthorized);

    private static readonly Error RefreshTokenReuseError = new(
        IdentityErrorCodes.RefreshTokenReuseDetected,
        "Refresh token reuse was detected and the session was revoked.",
        ErrorType.Unauthorized);

    private static readonly Error ConcurrencyError = new(
        IdentityErrorCodes.ConcurrencyConflict,
        "Concurrency conflict.",
        ErrorType.Conflict);

    public Task<StoredRefreshSession?> FindByTokenIdAsync(
        Guid tokenId,
        CancellationToken ct)
        => dbContext.RefreshSessions
            .AsNoTracking()
            .Where(session => session.TokenId == tokenId)
            .Select(session => Map(session))
            .SingleOrDefaultAsync(ct);

    public Task<StoredRefreshSession?> FindActiveBySessionIdAsync(
        Guid sessionId,
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct)
        => dbContext.RefreshSessions
            .AsNoTracking()
            .Where(session =>
                session.SessionId == sessionId
                && session.UserId == userId
                && session.RotatedAt == null
                && session.RevokedAt == null
                && session.ExpiresAt > now)
            .Select(session => Map(session))
            .SingleOrDefaultAsync(ct);

    public async Task<OperationResult> CreateAsync(
        NewRefreshSession session,
        DateTimeOffset now,
        CancellationToken ct)
    {
        dbContext.RefreshSessions.Add(CreateEntity(session, now));
        await dbContext.SaveChangesAsync(ct);
        return OperationResultFactory.Success();
    }

    public async Task<OperationResult> RotateAsync(
        Guid tokenId,
        long expectedVersion,
        string expectedTokenHash,
        NewRefreshSession replacement,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var current = await dbContext.RefreshSessions
            .SingleOrDefaultAsync(
                session => session.TokenId == tokenId,
                ct);

        if (current is null
            || !string.Equals(
                current.TokenHash,
                expectedTokenHash,
                StringComparison.Ordinal)
            || current.ExpiresAt <= now)
        {
            Detach(current);
            return OperationResultFactory.Fail(RefreshTokenInvalidError);
        }

        if (current.RotatedAt is not null)
        {
            await RevokeSessionAsync(current.SessionId, now, ct);
            return OperationResultFactory.Fail(RefreshTokenReuseError);
        }

        if (current.RevokedAt is not null)
        {
            Detach(current);
            return OperationResultFactory.Fail(RefreshTokenInvalidError);
        }

        if (current.Version != expectedVersion)
        {
            Detach(current);
            return OperationResultFactory.Fail(ConcurrencyError);
        }

        ValidateReplacement(current, replacement);

        current.RotatedAt = now;
        current.ReplacedByTokenId = replacement.TokenId;
        current.ModifiedAt = now;
        current.Version = checked(current.Version + 1);

        var replacementEntity = CreateEntity(replacement, now);
        dbContext.RefreshSessions.Add(replacementEntity);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(current);
            Detach(replacementEntity);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
        catch (DbUpdateException)
        {
            Detach(current);
            Detach(replacementEntity);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
    }

    public async Task<int> RevokeSessionAsync(
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken ct)
        => await RevokeAsync(
            dbContext.RefreshSessions.Where(
                session => session.SessionId == sessionId),
            now,
            ct);

    public async Task<int> RevokeAllAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct)
        => await RevokeAsync(
            dbContext.RefreshSessions.Where(
                session => session.UserId == userId),
            now,
            ct);

    public async Task<int> PruneAsync(
        DateTimeOffset expiredBefore,
        int maxCount,
        CancellationToken ct)
    {
        if (maxCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxCount));
        }

        for (var attempt = 0; attempt < MaximumConcurrencyRetries; attempt++)
        {
            var sessions = await dbContext.RefreshSessions
                .Where(session => session.ExpiresAt < expiredBefore)
                .OrderBy(session => session.ExpiresAt)
                .Take(maxCount)
                .ToListAsync(ct);

            if (sessions.Count == 0)
            {
                return 0;
            }

            dbContext.RefreshSessions.RemoveRange(sessions);

            try
            {
                await dbContext.SaveChangesAsync(ct);
                return sessions.Count;
            }
            catch (DbUpdateConcurrencyException) when (
                attempt + 1 < MaximumConcurrencyRetries)
            {
                foreach (var session in sessions)
                {
                    Detach(session);
                }
            }
        }

        throw new InvalidOperationException(
            "Could not prune refresh sessions due to concurrent changes.");
    }

    private async Task<int> RevokeAsync(
        IQueryable<RefreshSessionEntity> query,
        DateTimeOffset now,
        CancellationToken ct)
    {
        for (var attempt = 0; attempt < MaximumConcurrencyRetries; attempt++)
        {
            var sessions = await query
                .Where(session => session.RevokedAt == null)
                .ToListAsync(ct);

            foreach (var session in sessions)
            {
                Revoke(session, now);
            }

            if (sessions.Count == 0)
            {
                return 0;
            }

            try
            {
                await dbContext.SaveChangesAsync(ct);
                return sessions.Count;
            }
            catch (DbUpdateConcurrencyException) when (
                attempt + 1 < MaximumConcurrencyRetries)
            {
                foreach (var session in sessions)
                {
                    Detach(session);
                }
            }
        }

        throw new InvalidOperationException(
            "Could not revoke refresh sessions due to concurrent changes.");
    }

    private static RefreshSessionEntity CreateEntity(
        NewRefreshSession session,
        DateTimeOffset now)
        => new()
        {
            TokenId = session.TokenId,
            SessionId = session.SessionId,
            UserId = session.UserId,
            TokenHash = session.TokenHash,
            SecurityStamp = session.SecurityStamp,
            Version = 1,
            ExpiresAt = session.ExpiresAt,
            CreatedAt = now,
            ModifiedAt = now,
        };

    private static StoredRefreshSession Map(
        RefreshSessionEntity session)
        => new(
            session.TokenId,
            session.SessionId,
            session.UserId,
            session.TokenHash,
            session.SecurityStamp,
            session.Version,
            session.ExpiresAt,
            session.CreatedAt,
            session.ModifiedAt,
            session.RotatedAt,
            session.RevokedAt,
            session.ReplacedByTokenId);

    private static void ValidateReplacement(
        RefreshSessionEntity current,
        NewRefreshSession replacement)
    {
        if (replacement.TokenId == current.TokenId
            || replacement.SessionId != current.SessionId
            || replacement.UserId != current.UserId
            || replacement.ExpiresAt != current.ExpiresAt
            || !string.Equals(
                replacement.SecurityStamp,
                current.SecurityStamp,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The replacement refresh token must preserve its session binding.",
                nameof(replacement));
        }
    }

    private static void Revoke(
        RefreshSessionEntity session,
        DateTimeOffset now)
    {
        session.RevokedAt = now;
        session.ModifiedAt = now;
        session.Version = checked(session.Version + 1);
    }

    private void Detach(object? entity)
    {
        if (entity is not null)
        {
            dbContext.Entry(entity).State = EntityState.Detached;
        }
    }
}
