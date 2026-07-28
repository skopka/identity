namespace Skopka.Identity.Ef.Entities;

public sealed class UserCredentialEntity
{
    public Guid UserId { get; set; }
    public string? PasswordVerifier { get; set; } // opaque string (argon2/pbkdf2/phc)
    public DateTimeOffset UpdatedAt { get; set; }

    public AuthUserEntity User { get; set; } = null!;
}