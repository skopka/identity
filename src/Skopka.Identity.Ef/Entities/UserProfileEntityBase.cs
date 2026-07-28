namespace Skopka.Identity.Ef.Entities;

/// <summary>
/// Базовый класс, чтобы навигация в AuthUserEntity была не generic.
/// </summary>
public abstract class UserProfileEntityBase
{
    public Guid UserId { get; set; }

    public string? UserName { get; set; } // display
    public string? Email { get; set; }    // display
    public string? Phone { get; set; }    // display

    public AuthUserEntity User { get; set; } = null!;
}