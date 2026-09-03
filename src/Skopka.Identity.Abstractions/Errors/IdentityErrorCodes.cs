namespace Skopka.Identity.Errors;

public static class IdentityErrorCodes
{
    public const string UserNotFound = "identity.user.not_found";
    public const string ConcurrencyConflict = "identity.concurrency.conflict";
    public const string Forbidden = "identity.user.forbidden";

    public const string DuplicateUserName = "identity.user_name.duplicate";
    public const string DuplicateEmail = "identity.email.duplicate";
    public const string DuplicatePhone = "identity.phone.duplicate";
    public const string DuplicateLoginIdentifier =
        "identity.login_identifier.duplicate";

    public const string Validation = "identity.validation.failed";
    public const string UserDeleted = "identity.user.deleted";

    public const string RoleNotFound = "identity.role.not_found";
    public const string DuplicateRoleName = "identity.role.name_duplicate";
    public const string RoleAlreadyAssigned = "identity.role.already_assigned";

    public const string PasswordAlreadySet = "identity.password.already_set";
    public const string PasswordNotSet = "identity.password.not_set";
    public const string InvalidPassword = "identity.password.invalid";
    public const string PasswordRejected = "identity.password.rejected";
    public const string PasswordHasherUnavailable =
        "identity.password.hasher_unavailable";

    public const string InvalidCredentials = "identity.authentication.invalid_credentials";
    public const string AuthenticationBlocked = "identity.authentication.blocked";

    public const string ExternalLoginNotFound =
        "identity.external_login.not_found";
    public const string DuplicateExternalLogin =
        "identity.external_login.duplicate";

    public const string InvalidActionToken = "identity.token.invalid";
    public const string ActionTokenProviderUnavailable = "identity.token.provider_unavailable";

    public const string VerificationChallengeInvalid = "identity.verification.challenge_invalid";
    public const string VerificationResponseInvalid = "identity.verification.response_invalid";
    public const string VerificationAttemptsExceeded = "identity.verification.attempts_exceeded";
    public const string VerificationProofInvalid = "identity.verification.proof_invalid";
    public const string VerificationMethodUnavailable = "identity.verification.method_unavailable";

    public const string TotpAlreadyEnabled = "identity.totp.already_enabled";
    public const string TotpNotEnabled = "identity.totp.not_enabled";
    public const string TotpEnrollmentInvalid =
        "identity.totp.enrollment_invalid";
    public const string TotpCodeInvalid = "identity.totp.code_invalid";
    public const string TotpSecretUnavailable =
        "identity.totp.secret_unavailable";

    public const string StepUpPolicyUnavailable = "identity.step_up.policy_unavailable";
    public const string StepUpMethodNotAllowed = "identity.step_up.method_not_allowed";

    public const string DeviceAuthorizationInvalid =
        "identity.device_authorization.invalid";
    public const string DeviceAuthorizationVerifierInvalid =
        "identity.device_authorization.verifier_invalid";
    public const string DeviceAuthorizationStateInvalid =
        "identity.device_authorization.state_invalid";
    public const string DeviceAuthorizationStepUpInvalid =
        "identity.device_authorization.step_up_invalid";

    public const string WebAuthnClientDataInvalid =
        "identity.webauthn.client_data_invalid";
    public const string WebAuthnCeremonyMismatch =
        "identity.webauthn.ceremony_mismatch";
    public const string WebAuthnChallengeMismatch =
        "identity.webauthn.challenge_mismatch";
    public const string WebAuthnOriginNotAllowed =
        "identity.webauthn.origin_not_allowed";
    public const string WebAuthnRelyingPartyMismatch =
        "identity.webauthn.relying_party_mismatch";
    public const string WebAuthnUserNotPresent =
        "identity.webauthn.user_not_present";
    public const string WebAuthnUserNotVerified =
        "identity.webauthn.user_not_verified";
    public const string WebAuthnAttestationInvalid =
        "identity.webauthn.attestation_invalid";
    public const string WebAuthnAlgorithmNotSupported =
        "identity.webauthn.algorithm_not_supported";
    public const string WebAuthnSignatureInvalid =
        "identity.webauthn.signature_invalid";
    public const string WebAuthnCounterRegressed =
        "identity.webauthn.counter_regressed";
    public const string WebAuthnCredentialAlreadyRegistered =
        "identity.webauthn.credential_already_registered";
    public const string WebAuthnCredentialNotFound =
        "identity.webauthn.credential_not_found";

    public const string RateLimitExceeded = "identity.rate_limit.exceeded";


    public const string AccessTokenInvalid = "identity.session.access_token_invalid";
    public const string SessionInvalid = "identity.session.invalid";
    public const string RefreshTokenInvalid = "identity.session.refresh_token_invalid";
    public const string RefreshTokenReuseDetected =
        "identity.session.refresh_token_reuse_detected";
}
