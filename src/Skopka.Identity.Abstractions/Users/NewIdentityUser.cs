namespace Skopka.Identity.Users;

public sealed record NewIdentityUser<TProfile>(
    string? UserName,
    string? Email,
    string? Phone,
    TProfile Profile,
    UserFlags Flags,
    string SecurityStamp,
    Guid? Id = null)
{
    /// <summary>Scope of <see cref="Phone"/>; see <see cref="IdentityPhoneScopes"/>.</summary>
    public string PhoneScope { get; init; } = IdentityPhoneScopes.Default;
}
