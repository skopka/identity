namespace Skopka.Identity.Ef.Entities;

public sealed class LoginIdentifierEntity
{
    public Guid UserId { get; set; }

    public string NormalizedKey { get; set; } = null!;

    public bool IsActive { get; set; }

    public AuthUserEntity User { get; set; } = null!;
}
