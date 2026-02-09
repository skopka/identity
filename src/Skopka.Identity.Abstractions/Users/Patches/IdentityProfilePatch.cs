namespace Skopka.Identity.Users.Patches;

public record IdentityProfilePatch(string? FirstName = null, string? LastName = null, string? MiddleName = null, DateOnly? BirthDate = null);
