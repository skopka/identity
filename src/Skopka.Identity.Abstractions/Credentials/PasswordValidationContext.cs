using Skopka.Identity.Users;

namespace Skopka.Identity.Credentials;

public sealed record PasswordValidationContext<TProfile>(
    IdentityUser<TProfile> User,
    string Password,
    PasswordMutation Mutation);
