namespace Skopka.Identity.Roles;

public sealed class DefaultIdentityRoleNormalizer : IIdentityRoleNormalizer
{
    public string? NormalizeName(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? null
            : value.Trim().ToUpperInvariant();
}
