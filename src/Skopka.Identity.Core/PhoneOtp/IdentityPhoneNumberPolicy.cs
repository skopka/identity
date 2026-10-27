using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Errors;

namespace Skopka.Identity.PhoneOtp;

public sealed class IdentityPhoneNumberPolicy(
    IIdentityNormalizer normalizer, PhoneOtpOptions options) : IIdentityPhoneNumberPolicy
{
    public OperationResult<string> Normalize(string? phone)
    {
        var digits = phone is not null && phone.Length <= IdentityLoginLimits.MaximumLoginLength
            && phone.TrimStart().StartsWith('+')
                ? normalizer.NormalizePhoneLoginIdentifier(phone) : null;
        if (digits is null || digits.Length is < 8 or > 15
            || digits.Any(c => c is < '0' or > '9'))
        {
            return Fail(IdentityErrorCodes.PhoneInvalidFormat, "A valid E.164 phone number is required.");
        }

        var canonical = "+" + digits;
        if (options.AllowedCountryCodes.Count > 0
            && !options.AllowedCountryCodes.Any(prefix => canonical.StartsWith(prefix, StringComparison.Ordinal)))
        {
            return Fail(IdentityErrorCodes.PhoneCountryNotAllowed, "The phone country code is not allowed.");
        }
        return OperationResultFactory.Success(canonical);
    }

    private OperationResult<string> Fail(string code, string message)
        => OperationResultFactory.Fail<string>(new Error(code, message, ErrorType.Validation,
            new ValidationDetails(new Dictionary<string, string[]> { ["phone"] = [message] })
            {
                AllowedPhoneCountryCodes = code == IdentityErrorCodes.PhoneCountryNotAllowed
                ? options.AllowedCountryCodes.ToArray() : null
            }));
}
