namespace Skopka.Identity.SecurityEvents;

public sealed record IdentitySecurityEvent(
    Guid EventId,
    string Type,
    DateTimeOffset OccurredAt,
    Guid? UserId,
    Guid? ResourceId = null);
