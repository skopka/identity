namespace Skopka.Identity.Errors;

public static class IdentityErrorCodes
{
    public const string UserNotFound = "identity.user.not_found";
    public const string ConcurrencyConflict = "identity.concurrency.conflict";
    public const string Forbidden = "identity.user.forbidden";

    public const string DuplicateUserName = "identity.user_name.duplicate";
    public const string DuplicateEmail    = "identity.email.duplicate";
    public const string DuplicatePhone    = "identity.phone.duplicate";

    public const string Validation = "identity.validation.failed";
    public const string UserDeleted = "identity.user.deleted";

    public const string PasswordAlreadySet = "identity.password.already_set";
    public const string PasswordNotSet = "identity.password.not_set";
    public const string InvalidPassword = "identity.password.invalid";

    public const string InvalidCredentials = "identity.authentication.invalid_credentials";
    public const string AuthenticationBlocked = "identity.authentication.blocked";
}
