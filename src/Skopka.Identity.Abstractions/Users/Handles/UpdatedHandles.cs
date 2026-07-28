namespace Skopka.Identity.Users.Handles;

public sealed record UpdatedHandles(
    string? UserName, string? NormalizedUserName,
    string? Email,    string? NormalizedEmail,  bool EmailConfirmed,
    string? Phone,    string? NormalizedPhone,  bool PhoneConfirmed);