using Skopka.Identity.DeviceAuthorization;

namespace Skopka.Identity.Ef.Entities;

public sealed class DeviceAuthorizationRequestEntity
{
    public Guid Id { get; set; }
    public string DeviceCode { get; set; } = null!;
    public string BrowserVerifierHash { get; set; } = null!;
    public string UserCode { get; set; } = null!;
    public DeviceAuthorizationState State { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? DeviceDisplayName { get; set; }
    public string? ClientId { get; set; }
    public string? ReturnUrl { get; set; }
    public string? SessionClientName { get; set; }
    public string? SessionDeviceName { get; set; }
    public Guid? ResolvedByUserId { get; set; }
    public string? ApprovedSecurityStamp { get; set; }
    public Guid? ConsumptionId { get; set; }
    public Guid? SessionId { get; set; }
    public long Version { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
    public DateTimeOffset? ResolvedAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}
