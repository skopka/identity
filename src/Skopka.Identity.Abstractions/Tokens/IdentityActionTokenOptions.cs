namespace Skopka.Identity.Tokens;

public sealed class IdentityActionTokenOptions
{
    public TimeSpan EmailConfirmationLifetime { get; set; } = TimeSpan.FromDays(1);

    public TimeSpan PhoneConfirmationLifetime { get; set; } = TimeSpan.FromMinutes(10);

    public TimeSpan PasswordResetLifetime { get; set; } = TimeSpan.FromHours(1);
}
