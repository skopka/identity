using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Sessions;

public interface IIdentitySessionStore<TProfile>
{
    Task<StoredIdentitySession?> FindByIdAsync(
        Guid sessionId,
        Guid userId,
        CancellationToken ct);

    Task<OperationResult> CreateAsync(
        NewIdentitySession session,
        DateTimeOffset now,
        CancellationToken ct);

    Task<int> RevokeSessionAsync(
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<int> RevokeUserSessionAsync(
        Guid userId,
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<int> RevokeAllAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<IReadOnlyList<IdentitySessionInfo>> ListActiveAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<int> PruneAsync(
        DateTimeOffset expiredBefore,
        int maxCount,
        CancellationToken ct);
}
