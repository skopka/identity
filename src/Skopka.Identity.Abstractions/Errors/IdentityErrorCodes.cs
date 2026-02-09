namespace Skopka.Identity.Errors;

public static class IdentityErrorCodes
{
    public const string NotFound = "identity.user.not_found";
    public const string ConcurrencyConflict = "identity.concurrency.conflict";
    public const string Forbidden = "identity.user.forbidden";

    public const string DuplicateUserName = "identity.user_name.duplicate";
    public const string DuplicateEmail    = "identity.email.duplicate";
    public const string DuplicatePhone    = "identity.phone.duplicate";

    public const string Validation = "identity.validation.failed";
    public const string InvalidStateDeleted = "identity.user.deleted";
}
