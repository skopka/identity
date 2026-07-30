namespace Skopka.Identity.SecurityEvents;

/// <summary>
/// Observes committed security changes. Implementations must be non-blocking and
/// must not throw. Use an outbox in the host when durable audit delivery is required.
/// </summary>
public interface IIdentitySecurityEventObserver
{
    void OnEvent(IdentitySecurityEvent securityEvent);
}
