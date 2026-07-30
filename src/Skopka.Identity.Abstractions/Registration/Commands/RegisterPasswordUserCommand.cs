using Skopka.Identity.Users.Commands;

namespace Skopka.Identity.Registration;

public sealed record RegisterPasswordUserCommand<TProfile>(
    CreateUserCommand<TProfile> User,
    string Password);
