namespace Skopka.Identity;

public interface IIdentityNormalizer
{
    string? NormalizeUserName(string? value);
    string? NormalizeEmail(string? value);
    string? NormalizePhone(string? value);
}