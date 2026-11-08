namespace Skopka.Identity.Users.Handles;

public sealed record UpdatedHandles(
    string? UserName, string? NormalizedUserName,
    string? Email,    string? NormalizedEmail,  bool EmailConfirmed,
    string? Phone,    string? NormalizedPhone,  bool PhoneConfirmed,
    IReadOnlyCollection<string>? LoginIdentifierKeys = null)
{
    public UpdatedHandles(
        string? userName,
        string? normalizedUserName,
        string? email,
        string? normalizedEmail,
        bool emailConfirmed,
        string? phone,
        string? normalizedPhone,
        bool phoneConfirmed)
        : this(
            userName,
            normalizedUserName,
            email,
            normalizedEmail,
            emailConfirmed,
            phone,
            normalizedPhone,
            phoneConfirmed,
            null)
    {
    }

    /// <summary>
    /// Validated new scope of the phone. <see langword="null"/> keeps the stored scope, so
    /// changing a user name or email never moves a phone between scopes.
    /// </summary>
    public string? PhoneScope { get; init; }

    public void Deconstruct(
        out string? userName,
        out string? normalizedUserName,
        out string? email,
        out string? normalizedEmail,
        out bool emailConfirmed,
        out string? phone,
        out string? normalizedPhone,
        out bool phoneConfirmed)
    {
        userName = UserName;
        normalizedUserName = NormalizedUserName;
        email = Email;
        normalizedEmail = NormalizedEmail;
        emailConfirmed = EmailConfirmed;
        phone = Phone;
        normalizedPhone = NormalizedPhone;
        phoneConfirmed = PhoneConfirmed;
    }
}
