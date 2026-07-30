using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Users.Commands;

namespace Skopka.Identity.Registration;

public sealed record RegisterExternalUserCommand<TProfile>(
    CreateUserCommand<TProfile> User,
    ExternalLoginKey Login);
