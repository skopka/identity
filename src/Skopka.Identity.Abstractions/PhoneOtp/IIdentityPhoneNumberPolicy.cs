using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.PhoneOtp;

public interface IIdentityPhoneNumberPolicy
{
    OperationResult<string> Normalize(string? phone);
}
