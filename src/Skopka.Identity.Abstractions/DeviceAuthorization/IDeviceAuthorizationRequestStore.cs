using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Sessions;

namespace Skopka.Identity.DeviceAuthorization;

public interface IDeviceAuthorizationRequestStore<TProfile>
{
    Task<OperationResult> CreateAsync(
        NewDeviceAuthorizationRequest request,
        DateTimeOffset now,
        CancellationToken ct);

    /// <summary>Persists scope or fails closed if a legacy store does not support it.</summary>
    Task<OperationResult> CreateScopedAsync(NewDeviceAuthorizationRequest request, DateTimeOffset now, CancellationToken ct)
        => request.Scope is null ? CreateAsync(request, now, ct)
            : Task.FromResult(OperationResultFactory.Fail(new Error("identity.device_authorization.invalid", "Device authorization is invalid.", ErrorType.Unauthorized)));

    Task<StoredDeviceAuthorizationRequest?> FindByDeviceCodeAsync(
        string deviceCode,
        CancellationToken ct);

    Task<IReadOnlyList<StoredDeviceAuthorizationRequest>>
        FindPendingByUserCodeAsync(
            string userCode,
            DateTimeOffset now,
            int maxCount,
            CancellationToken ct);

    Task<OperationResult<StoredDeviceAuthorizationRequest>> ApproveAsync(
        Guid requestId,
        long expectedVersion,
        Guid userId,
        string securityStamp,
        DateTimeOffset now,
        CancellationToken ct);

    /// <summary>Persists trusted session context with approval. Legacy stores fail closed for non-null context.</summary>
    Task<OperationResult<StoredDeviceAuthorizationRequest>> ApproveAsync(
        Guid requestId, long expectedVersion, Guid userId, string securityStamp,
        IdentitySessionContext? context, DateTimeOffset now, CancellationToken ct)
        => context is null ? ApproveAsync(requestId, expectedVersion, userId, securityStamp, now, ct)
            : Task.FromResult(OperationResultFactory.Fail<StoredDeviceAuthorizationRequest>(
                new Error("identity.device_authorization.invalid", "Device authorization is invalid.", ErrorType.Unauthorized)));

    Task<OperationResult<StoredDeviceAuthorizationRequest>> DenyAsync(
        Guid requestId,
        long expectedVersion,
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<StoredDeviceAuthorizationRequest>> BeginConsumeAsync(
        Guid requestId,
        long expectedVersion,
        Guid consumptionId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult> CompleteConsumeAsync(
        Guid requestId,
        Guid consumptionId,
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<StoredDeviceAuthorizationRequest>> ReleaseConsumeAsync(
        Guid requestId,
        Guid consumptionId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<bool>> ExpireAsync(
        Guid requestId,
        long expectedVersion,
        DateTimeOffset now,
        CancellationToken ct);

    Task<int> PruneAsync(
        DateTimeOffset expiredBefore,
        int maxCount,
        CancellationToken ct);
}
