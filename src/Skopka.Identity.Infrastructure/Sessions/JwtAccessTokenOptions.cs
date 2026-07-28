namespace Skopka.Identity.Sessions;

public sealed class JwtAccessTokenOptions
{
    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;

    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
}
