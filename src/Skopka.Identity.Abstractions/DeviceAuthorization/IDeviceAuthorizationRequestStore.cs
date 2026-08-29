using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.DeviceAuthorization;

public interface IDeviceAuthorizationRequestStore<TProfile>
{
    Task<OperationResult> CreateAsync(
        NewDeviceAuthorizationRequest request,
        DateTimeOffset now,
        CancellationToken ct);

    Task<StoredDeviceAuthorizationRequest?> FindByDeviceCodeAsync(
        string deviceCode,
        CancellationToken ct);

    Task<OperationResult<StoredDeviceAuthorizationRequest>> ApproveAsync(
        Guid requestId,
        long expectedVersion,
        Guid userId,
        string securityStamp,
        DateTimeOffset now,
        CancellationToken ct);

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
