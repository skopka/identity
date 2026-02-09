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
    DateTimeOffset? DeletedAt,
    DateTimeOffset? BlockedAt,
    DateTimeOffset? BlockedUntil,
    DateTimeOffset CreatedAt,
    DateTimeOffset ModifiedAt);
    
    
