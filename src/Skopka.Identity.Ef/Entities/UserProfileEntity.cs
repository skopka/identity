namespace Skopka.Identity.Ef.Entities;

public sealed class UserProfileEntity<TProfile> : UserProfileEntityBase
{
    public TProfile Profile { get; set; } = default!;
}