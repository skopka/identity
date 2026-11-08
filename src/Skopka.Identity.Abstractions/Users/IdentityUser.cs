namespace Skopka.Identity.Users;

public record IdentityUser<TProfile>(
    Guid Id,
    UserFlags Flags,
    string? UserName,
    string? Email,
    bool EmailConfirmed,
    string? Phone,
    bool PhoneConfirmed,
    TProfile Profile,
    long Version,
    string SecurityStamp,
    DateTimeOffset? DeletedAt,
    DateTimeOffset? BlockedAt,
    DateTimeOffset? BlockedUntil,
    DateTimeOffset CreatedAt,
    DateTimeOffset ModifiedAt)
{
    /// <summary>
    /// Scope within which <see cref="Phone"/> is unique; <see cref="IdentityPhoneScopes.Default"/>
    /// unless the host placed the phone in a named scope.
    /// </summary>
    public string PhoneScope { get; init; } = IdentityPhoneScopes.Default;
}
    
    
