namespace Skopka.Identity.Users.Handles;

public sealed record NormalizedHandles(
    string? UserName,
    string? Email,
    string? Phone,
    IReadOnlyCollection<string>? LoginIdentifierKeys = null)
{
    public NormalizedHandles(
        string? userName,
        string? email,
        string? phone)
        : this(userName, email, phone, null)
    {
    }

    public void Deconstruct(
        out string? userName,
        out string? email,
        out string? phone)
    {
        userName = UserName;
        email = Email;
        phone = Phone;
    }
}
