using Skopka.Identity.Users.Commands;
using Skopka.Identity.Verification;

namespace Skopka.Identity.Registration;

public sealed record RegisterVerifiedPhoneUserCommand<TProfile>(
    CreateUserCommand<TProfile> User,
    VerificationProof Proof);
