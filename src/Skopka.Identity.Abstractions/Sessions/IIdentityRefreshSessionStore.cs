using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Sessions;

public interface IIdentityRefreshSessionStore<TProfile>
{
    Task<StoredRefreshSession?> FindByTokenIdAsync(
        Guid tokenId,
        CancellationToken ct);

    Task<StoredRefreshSession?> FindActiveBySessionIdAsync(
        Guid sessionId,
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult> CreateAsync(
        NewRefreshSession session,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult> RotateAsync(
        Guid tokenId,
        long expectedVersion,
        string expectedTokenHash,
        NewRefreshSession replacement,
        DateTimeOffset now,
        CancellationToken ct);

    Task<int> RevokeSessionAsync(
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<int> RevokeAllAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<int> PruneAsync(
        DateTimeOffset expiredBefore,
        int maxCount,
        CancellationToken ct);
}
