namespace Skopka.Identity.Users;

public record IdentityProfile(string? FirstName, string? LastName, string? MiddleName, DateOnly? BirthDate);
