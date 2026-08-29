namespace Skopka.Identity.SecurityEvents;

public static class IdentitySecurityEventTypes
{
    public const string UserCreated = "identity.user.created";
    public const string PasswordUserRegistered =
        "identity.registration.password";
    public const string ExternalUserRegistered =
        "identity.registration.external";
    public const string ExternalLoginLinked =
        "identity.external_login.linked";
    public const string ExternalLoginUnlinked =
        "identity.external_login.unlinked";
    public const string PasswordSet = "identity.password.set";
    public const string PasswordChanged = "identity.password.changed";
    public const string PasswordRemoved = "identity.password.removed";
    public const string PasswordReset = "identity.password.reset";
    public const string SessionCreated = "identity.session.created";
    public const string SessionRefreshed = "identity.session.refreshed";
    public const string SessionRevoked = "identity.session.revoked";
    public const string SessionsRevoked = "identity.session.revoked_all";
    public const string DeviceAuthorizationCreated =
        "identity.device_authorization.created";
    public const string DeviceAuthorizationApproved =
        "identity.device_authorization.approved";
    public const string DeviceAuthorizationDenied =
        "identity.device_authorization.denied";
    public const string DeviceAuthorizationExpired =
        "identity.device_authorization.expired";
    public const string DeviceAuthorizationConsumed =
        "identity.device_authorization.consumed";
    public const string RoleAssigned = "identity.role.assigned";
    public const string RoleRemoved = "identity.role.removed";
    public const string UserNameChanged = "identity.user_name.changed";
    public const string EmailChanged = "identity.email.changed";
    public const string EmailConfirmed = "identity.email.confirmed";
    public const string PhoneChanged = "identity.phone.changed";
    public const string PhoneConfirmed = "identity.phone.confirmed";
    public const string UserBlocked = "identity.user.blocked";
    public const string UserUnblocked = "identity.user.unblocked";
    public const string UserDeleted = "identity.user.deleted";
    public const string UserRestored = "identity.user.restored";
}
