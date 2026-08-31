using Skopka.Identity.StepUp;

namespace Skopka.Identity.DeviceAuthorization;

public sealed record CreateDeviceAuthorizationRequestCommand(
    DeviceAuthorizationMetadata Metadata,
    string? ClientKey = null);

public sealed record GetDeviceAuthorizationStatusCommand(
    string DeviceCode,
    string BrowserVerifier,
    string? ClientKey = null);

public sealed record GetDeviceAuthorizationApprovalDetailsCommand(
    string DeviceCode,
    string? ClientKey = null);

public sealed record GetDeviceAuthorizationApprovalDetailsByUserCodeCommand(
    string UserCode,
    string? ClientKey = null);

public sealed record ApproveDeviceAuthorizationRequestCommand(
    string DeviceCode,
    Guid UserId,
    StepUpDecision StepUpDecision);

public sealed record DenyDeviceAuthorizationRequestCommand(
    string DeviceCode,
    Guid UserId);

public sealed record ConsumeDeviceAuthorizationRequestCommand(
    string DeviceCode,
    string BrowserVerifier);
