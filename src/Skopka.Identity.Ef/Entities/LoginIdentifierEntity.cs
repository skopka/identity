namespace Skopka.Identity.Ef.Entities;

public sealed class LoginIdentifierEntity
{
    public Guid UserId { get; set; }

    public string NormalizedKey { get; set; } = null!;

    public bool IsActive { get; set; }

    /// <summary>Copy of the owner's phone scope; the active key is unique within it.</summary>
    public string PhoneScope { get; set; } = "";

    public AuthUserEntity User { get; set; } = null!;
}
