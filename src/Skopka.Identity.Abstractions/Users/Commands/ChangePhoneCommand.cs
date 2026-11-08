namespace Skopka.Identity.Users.Commands;

public record ChangePhoneCommand(Guid UserId, long ExpectedVersion, string? NewPhone)
{
    /// <summary>
    /// Trusted, server-selected scope for the new phone. <see langword="null"/> keeps the
    /// user's current scope. Removing the phone returns the user to the default scope.
    /// </summary>
    public string? PhoneScope { get; init; }
}
