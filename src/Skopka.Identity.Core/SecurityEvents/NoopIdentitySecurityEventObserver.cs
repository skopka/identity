namespace Skopka.Identity.SecurityEvents;

public sealed class NoopIdentitySecurityEventObserver
    : IIdentitySecurityEventObserver
{
    public void OnEvent(IdentitySecurityEvent securityEvent)
    {
    }
}
