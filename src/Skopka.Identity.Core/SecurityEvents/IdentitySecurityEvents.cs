namespace Skopka.Identity.SecurityEvents;

internal static class IdentitySecurityEvents
{
    public static void Observe(
        this IIdentitySecurityEventObserver? observer,
        string type,
        DateTimeOffset occurredAt,
        Guid? userId,
        Guid? resourceId = null)
        => observer?.OnEvent(
            new IdentitySecurityEvent(
                Guid.NewGuid(),
                type,
                occurredAt,
                userId,
                resourceId));
}
