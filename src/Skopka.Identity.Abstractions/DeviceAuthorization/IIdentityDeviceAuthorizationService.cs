using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.DeviceAuthorization;

public interface IIdentityDeviceAuthorizationService<TProfile>
{
    Task<OperationResult<CreatedDeviceAuthorizationRequest>> CreateAsync(
        CreateDeviceAuthorizationRequestCommand command,
        CancellationToken ct);

    Task<OperationResult<DeviceAuthorizationStatus>> GetStatusAsync(
        GetDeviceAuthorizationStatusCommand command,
        CancellationToken ct);

    Task<OperationResult<DeviceAuthorizationApprovalDetails>>
        GetApprovalDetailsAsync(
            GetDeviceAuthorizationApprovalDetailsCommand command,
            CancellationToken ct);

    Task<OperationResult<DeviceAuthorizationApprovalDetails>>
        GetApprovalDetailsByUserCodeAsync(
            GetDeviceAuthorizationApprovalDetailsByUserCodeCommand command,
            CancellationToken ct);

    Task<OperationResult> ApproveAsync(
        ApproveDeviceAuthorizationRequestCommand command,
        CancellationToken ct);

    Task<OperationResult> DenyAsync(
        DenyDeviceAuthorizationRequestCommand command,
        CancellationToken ct);

    Task<OperationResult<ConsumedDeviceAuthorizationRequest>> ConsumeAsync(
        ConsumeDeviceAuthorizationRequestCommand command,
        CancellationToken ct);

    Task<int> PruneAsync(CancellationToken ct);
}
