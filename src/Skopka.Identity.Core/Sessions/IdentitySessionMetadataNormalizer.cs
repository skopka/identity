using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

internal static class IdentitySessionMetadataNormalizer
{
    public static (IdentitySessionMetadata? Value, Error? Error) Normalize(
        IdentitySessionMetadata? metadata)
    {
        if (metadata is null)
        {
            return (null, null);
        }

        var clientName = NormalizeLabel(metadata.ClientName);
        if (clientName?.Length > SessionLimits.MaximumClientNameLength)
        {
            return (
                null,
                IdentityErrors.Validation(
                    "metadata.clientName",
                    $"ClientName cannot exceed {SessionLimits.MaximumClientNameLength} characters."));
        }

        var deviceName = NormalizeLabel(metadata.DeviceName);
        if (deviceName?.Length > SessionLimits.MaximumDeviceNameLength)
        {
            return (
                null,
                IdentityErrors.Validation(
                    "metadata.deviceName",
                    $"DeviceName cannot exceed {SessionLimits.MaximumDeviceNameLength} characters."));
        }

        return (
            clientName is null && deviceName is null
                ? null
                : new IdentitySessionMetadata(clientName, deviceName),
            null);
    }

    private static string? NormalizeLabel(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
