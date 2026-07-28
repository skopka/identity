using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Skopka.Identity.Sessions;

public sealed class IdentityJwtBearerOptions
{
    public string AuthenticationScheme { get; set; } =
        JwtBearerDefaults.AuthenticationScheme;

    public bool SetAsDefaultScheme { get; set; } = true;

    public bool ValidateSessionOnEveryRequest { get; set; }
}
