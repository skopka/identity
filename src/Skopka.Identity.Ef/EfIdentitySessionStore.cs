using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.Sessions;

namespace Skopka.Identity.Ef;

public sealed class EfIdentitySessionStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IIdentityRefreshSessionStore<TProfile>,
        IIdentitySessionStore<TProfile>
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

    public async Task<StoredIdentitySession?> FindByIdAsync(
        Guid sessionId,
        Guid userId,
        CancellationToken ct)
    {
        var session = await dbContext.Sessions
            .AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.SessionId == sessionId
                    && item.UserId == userId,
                ct);
        return session is null ? null : Map(session);
    }

    public async Task<StoredRefreshSession?> FindByTokenIdAsync(
        Guid tokenId,
        CancellationToken ct)
    {
        var token = await dbContext.RefreshSessions
            .AsNoTracking()
            .Include(item => item.Session)
            .SingleOrDefaultAsync(item => item.TokenId == tokenId, ct);
        return token is null ? null : Map(token);
    }

    public async Task<StoredRefreshSession?> FindActiveBySessionIdAsync(
        Guid sessionId,
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var token = await dbContext.RefreshSessions
            .AsNoTracking()
            .Include(item => item.Session)
            .Where(item =>
                item.SessionId == sessionId
                && item.Session.UserId == userId
                && item.RotatedAt == null
                && item.Session.RevokedAt == null
                && item.Session.ExpiresAt > now)
            .SingleOrDefaultAsync(ct);
        return token is null ? null : Map(token);
    }

    public async Task<OperationResult> CreateAsync(
        NewIdentitySession session,
        DateTimeOffset now,
        CancellationToken ct)
    {
        dbContext.Sessions.Add(CreateEntity(session, now));
        await dbContext.SaveChangesAsync(ct);
        return OperationResultFactory.Success();
    }

    public async Task<OperationResult> CreateAsync(
        NewRefreshSession session,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var parent = CreateEntity(
            new NewIdentitySession(
                session.SessionId,
                session.UserId,
                session.SecurityStamp,
                session.ExpiresAt,
                session.Metadata),
            now);
        parent.RefreshTokens.Add(CreateEntity(session, now));
        dbContext.Sessions.Add(parent);
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
            .Include(item => item.Session)
            .SingleOrDefaultAsync(item => item.TokenId == tokenId, ct);

        if (current is null
            || !string.Equals(
                current.TokenHash,
                expectedTokenHash,
                StringComparison.Ordinal)
            || current.Session.ExpiresAt <= now
            || current.Session.RevokedAt is not null)
        {
            Detach(current);
            return OperationResultFactory.Fail(RefreshTokenInvalidError);
        }

        if (current.RotatedAt is not null)
        {
            var sessionId = current.SessionId;
            Detach(current);
            await RevokeSessionAsync(sessionId, now, ct);
            return OperationResultFactory.Fail(RefreshTokenReuseError);
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
        current.Session.LastRefreshedAt = now;
        current.Session.Version = checked(current.Session.Version + 1);

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

    public Task<int> RevokeSessionAsync(
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken ct)
        => RevokeAsync(
            dbContext.Sessions.Where(
                session => session.SessionId == sessionId),
            now,
            ct);

    public Task<int> RevokeUserSessionAsync(
        Guid userId,
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken ct)
        => RevokeAsync(
            dbContext.Sessions.Where(
                session => session.UserId == userId
                    && session.SessionId == sessionId),
            now,
            ct);

    public Task<int> RevokeAllAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct)
        => RevokeAsync(
            dbContext.Sessions.Where(session => session.UserId == userId),
            now,
            ct);

    public async Task<IReadOnlyList<IdentitySessionInfo>> ListActiveAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct)
        => await dbContext.Sessions
            .AsNoTracking()
            .Where(session =>
                session.UserId == userId
                && session.RevokedAt == null
                && session.ExpiresAt > now)
            .OrderByDescending(session => session.LastRefreshedAt)
            .Select(session => new IdentitySessionInfo(
                session.SessionId,
                session.UserId,
                new IdentitySessionMetadata(
                    session.ClientName,
                    session.DeviceName),
                session.ExpiresAt,
                session.CreatedAt,
                session.LastRefreshedAt))
            .ToListAsync(ct);

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
            var sessions = await dbContext.Sessions
                .Where(session => session.ExpiresAt < expiredBefore)
                .OrderBy(session => session.ExpiresAt)
                .Take(maxCount)
                .ToListAsync(ct);

            if (sessions.Count == 0)
            {
                return 0;
            }

            dbContext.Sessions.RemoveRange(sessions);

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
            "Could not prune sessions due to concurrent changes.");
    }

    private async Task<int> RevokeAsync(
        IQueryable<IdentitySessionEntity> query,
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
                session.RevokedAt = now;
                session.Version = checked(session.Version + 1);
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
            "Could not revoke sessions due to concurrent changes.");
    }

    private static IdentitySessionEntity CreateEntity(
        NewIdentitySession session,
        DateTimeOffset now)
        => new()
        {
            SessionId = session.SessionId,
            UserId = session.UserId,
            SecurityStamp = session.SecurityStamp,
            ClientName = session.Metadata?.ClientName,
            DeviceName = session.Metadata?.DeviceName,
            Version = 1,
            ExpiresAt = session.ExpiresAt,
            CreatedAt = now,
            LastRefreshedAt = now,
        };

    private static RefreshSessionEntity CreateEntity(
        NewRefreshSession session,
        DateTimeOffset now)
        => new()
        {
            TokenId = session.TokenId,
            SessionId = session.SessionId,
            TokenHash = session.TokenHash,
            Version = 1,
            CreatedAt = now,
            ModifiedAt = now,
        };

    private static StoredIdentitySession Map(IdentitySessionEntity session)
        => new(
            session.SessionId,
            session.UserId,
            session.SecurityStamp,
            session.Version,
            session.ExpiresAt,
            session.CreatedAt,
            session.LastRefreshedAt,
            session.RevokedAt,
            new IdentitySessionMetadata(
                session.ClientName,
                session.DeviceName));

    private static StoredRefreshSession Map(RefreshSessionEntity token)
        => new(
            token.TokenId,
            token.SessionId,
            token.Session.UserId,
            token.TokenHash,
            token.Session.SecurityStamp,
            token.Version,
            token.Session.ExpiresAt,
            token.CreatedAt,
            token.ModifiedAt,
            token.RotatedAt,
            token.Session.RevokedAt,
            token.ReplacedByTokenId,
            new IdentitySessionMetadata(
                token.Session.ClientName,
                token.Session.DeviceName));

    private static void ValidateReplacement(
        RefreshSessionEntity current,
        NewRefreshSession replacement)
    {
        if (replacement.TokenId == current.TokenId
            || replacement.SessionId != current.SessionId
            || replacement.UserId != current.Session.UserId
            || replacement.ExpiresAt != current.Session.ExpiresAt
            || !string.Equals(
                replacement.SecurityStamp,
                current.Session.SecurityStamp,
                StringComparison.Ordinal)
            || !string.Equals(
                replacement.Metadata?.ClientName,
                current.Session.ClientName,
                StringComparison.Ordinal)
            || !string.Equals(
                replacement.Metadata?.DeviceName,
                current.Session.DeviceName,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The replacement refresh token must preserve its session binding.",
                nameof(replacement));
        }
    }

    private void Detach(object? entity)
    {
        if (entity is not null)
        {
            dbContext.Entry(entity).State = EntityState.Detached;
        }
    }
}
