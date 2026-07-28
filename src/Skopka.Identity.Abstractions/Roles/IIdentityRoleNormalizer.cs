namespace Skopka.Identity.Roles;

public interface IIdentityRoleNormalizer
{
    string? NormalizeName(string? value);
}
