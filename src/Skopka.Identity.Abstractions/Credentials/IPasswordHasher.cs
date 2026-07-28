namespace Skopka.Identity.Credentials;

public interface IPasswordHasher
{
    string HashPassword(string password);

    PasswordVerificationResult VerifyHashedPassword(
        string passwordVerifier,
        string providedPassword);
}
