using Skopka.Identity.Sessions;

namespace Skopka.Identity.DeviceAuthorization;

public sealed record DeviceAuthorizationMetadata(
    string? IpAddress,
    string? UserAgent,
    string? DeviceDisplayName,
    string? ClientId,
    string? ReturnUrl,
    IdentitySessionMetadata? SessionMetadata = null);

public sealed record CreatedDeviceAuthorizationRequest(
    Guid RequestId,
    string DeviceCode,
    string BrowserVerifier,
    string UserCode,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt);

public sealed record DeviceAuthorizationStatus(
    DeviceAuthorizationState State,
    string UserCode,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? ResolvedAt);

public sealed record DeviceAuthorizationApprovalDetails(
    Guid RequestId,
    string DeviceCode,
    string UserCode,
    DeviceAuthorizationState State,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    string? IpAddress,
    string? UserAgent,
    string? DeviceDisplayName);

public sealed record ConsumedDeviceAuthorizationRequest(
    IssuedIdentitySession Session,
    string? ClientId,
    string? ReturnUrl);

public sealed record NewDeviceAuthorizationRequest(
    Guid Id,
    string DeviceCode,
    string BrowserVerifierHash,
    string UserCode,
    DeviceAuthorizationMetadata Metadata,
    DateTimeOffset ExpiresAt);

public sealed record StoredDeviceAuthorizationRequest(
    Guid Id,
    string DeviceCode,
    string BrowserVerifierHash,
    string UserCode,
    DeviceAuthorizationState State,
    DeviceAuthorizationMetadata Metadata,
    Guid? ResolvedByUserId,
    string? ApprovedSecurityStamp,
    Guid? ConsumptionId,
    Guid? SessionId,
    long Version,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset ModifiedAt,
    DateTimeOffset? ResolvedAt,
    DateTimeOffset? ConsumedAt);
