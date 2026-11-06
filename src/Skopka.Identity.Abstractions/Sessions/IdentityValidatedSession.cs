using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

/// <summary>An online-validated user and the immutable assurance of their logical session.</summary>
public sealed record IdentityValidatedSession<TProfile>(IdentityUser<TProfile> User, IdentitySessionAssurance Assurance);
