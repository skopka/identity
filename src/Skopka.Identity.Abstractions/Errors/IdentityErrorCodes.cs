namespace Skopka.Identity.Errors;

public static class IdentityErrorCodes
{
    public const string UserNotFound = "identity.user.not_found";
    public const string ConcurrencyConflict = "identity.concurrency.conflict";
    public const string Forbidden = "identity.user.forbidden";

    public const string DuplicateUserName = "identity.user_name.duplicate";
    public const string DuplicateEmail = "identity.email.duplicate";
    public const string DuplicatePhone = "identity.phone.duplicate";

    public const string Validation = "identity.validation.failed";
    public const string UserDeleted = "identity.user.deleted";

    public const string RoleNotFound = "identity.role.not_found";
    public const string DuplicateRoleName = "identity.role.name_duplicate";
    public const string RoleAlreadyAssigned = "identity.role.already_assigned";

    public const string PasswordAlreadySet = "identity.password.already_set";
    public const string PasswordNotSet = "identity.password.not_set";
    public const string InvalidPassword = "identity.password.invalid";
    public const string PasswordRejected = "identity.password.rejected";

    public const string InvalidCredentials = "identity.authentication.invalid_credentials";
    public const string AuthenticationBlocked = "identity.authentication.blocked";

    public const string InvalidActionToken = "identity.token.invalid";
    public const string ActionTokenProviderUnavailable = "identity.token.provider_unavailable";

    public const string VerificationChallengeInvalid = "identity.verification.challenge_invalid";
    public const string VerificationResponseInvalid = "identity.verification.response_invalid";
    public const string VerificationAttemptsExceeded = "identity.verification.attempts_exceeded";
    public const string VerificationProofInvalid = "identity.verification.proof_invalid";
    public const string VerificationMethodUnavailable = "identity.verification.method_unavailable";

    public const string StepUpPolicyUnavailable = "identity.step_up.policy_unavailable";
    public const string StepUpMethodNotAllowed = "identity.step_up.method_not_allowed";

    public const string RateLimitExceeded = "identity.rate_limit.exceeded";

    public const string AccessTokenInvalid = "identity.session.access_token_invalid";
    public const string RefreshTokenInvalid = "identity.session.refresh_token_invalid";
    public const string RefreshTokenReuseDetected =
        "identity.session.refresh_token_reuse_detected";
}
