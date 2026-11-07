namespace Skopka.Identity.Sessions;

/// <summary>Trusted server-derived site scope and primary authentication method.</summary>
public sealed record IdentitySessionContext(string Scope, string AuthenticationMethod)
{
    /// <summary>Maximum length of either context value.</summary>
    public const int MaximumValueLength = 128;
}
