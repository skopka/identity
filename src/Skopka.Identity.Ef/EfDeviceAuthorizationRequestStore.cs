using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.DeviceAuthorization;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.Sessions;

namespace Skopka.Identity.Ef;

public sealed class EfDeviceAuthorizationRequestStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IDeviceAuthorizationRequestStore<TProfile>
{
    private const int MaximumConcurrencyRetries = 3;

    private static readonly Error StateError = new(
        IdentityErrorCodes.DeviceAuthorizationStateInvalid,
        "The device authorization request cannot be used in its current state.",
        ErrorType.Conflict);

    private static readonly Error ConcurrencyError = new(
        IdentityErrorCodes.ConcurrencyConflict,
        "Concurrency conflict.",
        ErrorType.Conflict);

    public async Task<OperationResult> CreateAsync(
        NewDeviceAuthorizationRequest request,
        DateTimeOffset now,
        CancellationToken ct)
    {
        dbContext.DeviceAuthorizationRequests.Add(
            new DeviceAuthorizationRequestEntity
            {
                Id = request.Id,
                DeviceCode = request.DeviceCode,
                BrowserVerifierHash = request.BrowserVerifierHash,
                UserCode = request.UserCode,
                State = DeviceAuthorizationState.Pending,
                IpAddress = request.Metadata.IpAddress,
                UserAgent = request.Metadata.UserAgent,
                DeviceDisplayName = request.Metadata.DeviceDisplayName,
                ClientId = request.Metadata.ClientId,
                ReturnUrl = request.Metadata.ReturnUrl,
                SessionClientName =
                    request.Metadata.SessionMetadata?.ClientName,
                SessionDeviceName =
                    request.Metadata.SessionMetadata?.DeviceName,
                Version = 1,
                CreatedAt = now,
                ExpiresAt = request.ExpiresAt,
                ModifiedAt = now,
            });
        await dbContext.SaveChangesAsync(ct);
        return OperationResultFactory.Success();
    }

    public Task<StoredDeviceAuthorizationRequest?> FindByDeviceCodeAsync(
        string deviceCode,
        CancellationToken ct)
        => dbContext.DeviceAuthorizationRequests
            .AsNoTracking()
            .Where(request => request.DeviceCode == deviceCode)
            .Select(request => Map(request))
            .SingleOrDefaultAsync(ct);

    public async Task<IReadOnlyList<StoredDeviceAuthorizationRequest>>
        FindPendingByUserCodeAsync(
            string userCode,
            DateTimeOffset now,
            int maxCount,
            CancellationToken ct)
    {
        if (maxCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxCount));
        }

        return await dbContext.DeviceAuthorizationRequests
            .AsNoTracking()
            .Where(request => request.UserCode == userCode
                && request.State == DeviceAuthorizationState.Pending
                && request.ExpiresAt > now)
            .OrderByDescending(request => request.CreatedAt)
            .Take(maxCount)
            .Select(request => Map(request))
            .ToListAsync(ct);
    }

    public Task<OperationResult<StoredDeviceAuthorizationRequest>> ApproveAsync(
        Guid requestId,
        long expectedVersion,
        Guid userId,
        string securityStamp,
        DateTimeOffset now,
        CancellationToken ct)
        => TransitionAsync(
            requestId,
            expectedVersion,
            DeviceAuthorizationState.Pending,
            now,
            request =>
            {
                request.State = DeviceAuthorizationState.Approved;
                request.ResolvedByUserId = userId;
                request.ApprovedSecurityStamp = securityStamp;
                request.ResolvedAt = now;
            },
            ct);

    public Task<OperationResult<StoredDeviceAuthorizationRequest>> DenyAsync(
        Guid requestId,
        long expectedVersion,
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct)
        => TransitionAsync(
            requestId,
            expectedVersion,
            DeviceAuthorizationState.Pending,
            now,
            request =>
            {
                request.State = DeviceAuthorizationState.Denied;
                request.ResolvedByUserId = userId;
                request.ResolvedAt = now;
            },
            ct);

    public Task<OperationResult<StoredDeviceAuthorizationRequest>>
        BeginConsumeAsync(
            Guid requestId,
            long expectedVersion,
            Guid consumptionId,
            DateTimeOffset now,
            CancellationToken ct)
        => TransitionAsync(
            requestId,
            expectedVersion,
            DeviceAuthorizationState.Approved,
            now,
            request =>
            {
                request.State = DeviceAuthorizationState.Consuming;
                request.ConsumptionId = consumptionId;
            },
            ct);

    public async Task<OperationResult> CompleteConsumeAsync(
        Guid requestId,
        Guid consumptionId,
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var entity = await dbContext.DeviceAuthorizationRequests
            .SingleOrDefaultAsync(request => request.Id == requestId, ct);
        if (entity is null)
        {
            return OperationResultFactory.Fail(StateError);
        }

        if (entity.State == DeviceAuthorizationState.Consumed
            && entity.ConsumptionId == consumptionId
            && entity.SessionId == sessionId)
        {
            Detach(entity);
            return OperationResultFactory.Success();
        }

        if (entity.State != DeviceAuthorizationState.Consuming
            || entity.ConsumptionId != consumptionId)
        {
            Detach(entity);
            return OperationResultFactory.Fail(StateError);
        }

        entity.State = DeviceAuthorizationState.Consumed;
        entity.SessionId = sessionId;
        entity.ConsumedAt = now;
        entity.ModifiedAt = now;
        entity.Version = checked(entity.Version + 1);
        return await SaveAsync(entity, ct);
    }

    public async Task<OperationResult<StoredDeviceAuthorizationRequest>>
        ReleaseConsumeAsync(
            Guid requestId,
            Guid consumptionId,
            DateTimeOffset now,
            CancellationToken ct)
    {
        var entity = await dbContext.DeviceAuthorizationRequests
            .SingleOrDefaultAsync(request => request.Id == requestId, ct);
        if (entity is null
            || entity.State != DeviceAuthorizationState.Consuming
            || entity.ConsumptionId != consumptionId)
        {
            Detach(entity);
            return OperationResultFactory.Fail<
                StoredDeviceAuthorizationRequest>(StateError);
        }

        entity.State = entity.ExpiresAt <= now
            ? DeviceAuthorizationState.Expired
            : DeviceAuthorizationState.Approved;
        entity.ConsumptionId = null;
        entity.ModifiedAt = now;
        entity.Version = checked(entity.Version + 1);

        var saved = await SaveAsync(entity, ct);
        return saved.IsSuccess
            ? OperationResultFactory.Success(Map(entity))
            : OperationResultFactory.Fail<
                StoredDeviceAuthorizationRequest>(saved.Errors);
    }

    public async Task<OperationResult<bool>> ExpireAsync(
        Guid requestId,
        long expectedVersion,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var entity = await dbContext.DeviceAuthorizationRequests
            .SingleOrDefaultAsync(request => request.Id == requestId, ct);
        if (entity is null)
        {
            return OperationResultFactory.Success(false);
        }

        if (entity.Version != expectedVersion)
        {
            Detach(entity);
            return OperationResultFactory.Fail<bool>(ConcurrencyError);
        }

        if (entity.ExpiresAt > now
            || entity.State is not (
                DeviceAuthorizationState.Pending
                or DeviceAuthorizationState.Approved))
        {
            Detach(entity);
            return OperationResultFactory.Success(false);
        }

        entity.State = DeviceAuthorizationState.Expired;
        entity.ModifiedAt = now;
        entity.Version = checked(entity.Version + 1);
        var saved = await SaveAsync(entity, ct);
        return saved.IsSuccess
            ? OperationResultFactory.Success(true)
            : OperationResultFactory.Fail<bool>(saved.Errors);
    }

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
            var expired = await dbContext.DeviceAuthorizationRequests
                .Where(request => request.ExpiresAt < expiredBefore)
                .OrderBy(request => request.ExpiresAt)
                .Take(maxCount)
                .ToListAsync(ct);
            if (expired.Count == 0)
            {
                return 0;
            }

            dbContext.DeviceAuthorizationRequests.RemoveRange(expired);
            try
            {
                await dbContext.SaveChangesAsync(ct);
                return expired.Count;
            }
            catch (DbUpdateConcurrencyException) when (
                attempt + 1 < MaximumConcurrencyRetries)
            {
                foreach (var request in expired)
                {
                    Detach(request);
                }
            }
        }

        throw new InvalidOperationException(
            "Could not prune device authorization requests due to concurrent changes.");
    }

    private async Task<OperationResult<StoredDeviceAuthorizationRequest>>
        TransitionAsync(
            Guid requestId,
            long expectedVersion,
            DeviceAuthorizationState requiredState,
            DateTimeOffset now,
            Action<DeviceAuthorizationRequestEntity> transition,
            CancellationToken ct)
    {
        var entity = await dbContext.DeviceAuthorizationRequests
            .SingleOrDefaultAsync(request => request.Id == requestId, ct);
        if (entity is null
            || entity.State != requiredState
            || entity.ExpiresAt <= now)
        {
            Detach(entity);
            return OperationResultFactory.Fail<
                StoredDeviceAuthorizationRequest>(StateError);
        }

        if (entity.Version != expectedVersion)
        {
            Detach(entity);
            return OperationResultFactory.Fail<
                StoredDeviceAuthorizationRequest>(ConcurrencyError);
        }

        transition(entity);
        entity.ModifiedAt = now;
        entity.Version = checked(expectedVersion + 1);
        var saved = await SaveAsync(entity, ct);
        return saved.IsSuccess
            ? OperationResultFactory.Success(Map(entity))
            : OperationResultFactory.Fail<
                StoredDeviceAuthorizationRequest>(saved.Errors);
    }

    private async Task<OperationResult> SaveAsync(
        DeviceAuthorizationRequestEntity entity,
        CancellationToken ct)
    {
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

    private static StoredDeviceAuthorizationRequest Map(
        DeviceAuthorizationRequestEntity request)
        => new(
            request.Id,
            request.DeviceCode,
            request.BrowserVerifierHash,
            request.UserCode,
            request.State,
            new DeviceAuthorizationMetadata(
                request.IpAddress,
                request.UserAgent,
                request.DeviceDisplayName,
                request.ClientId,
                request.ReturnUrl,
                request.SessionClientName is null
                    && request.SessionDeviceName is null
                        ? null
                        : new IdentitySessionMetadata(
                            request.SessionClientName,
                            request.SessionDeviceName)),
            request.ResolvedByUserId,
            request.ApprovedSecurityStamp,
            request.ConsumptionId,
            request.SessionId,
            request.Version,
            request.CreatedAt,
            request.ExpiresAt,
            request.ModifiedAt,
            request.ResolvedAt,
            request.ConsumedAt);

    private void Detach(object? entity)
    {
        if (entity is not null)
        {
            dbContext.Entry(entity).State = EntityState.Detached;
        }
    }
}
