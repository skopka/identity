namespace Skopka.Identity.Credentials;

public enum PasswordVerificationResult
{
    Failed = 0,
    Success = 1,
    SuccessRehashNeeded = 2
}
