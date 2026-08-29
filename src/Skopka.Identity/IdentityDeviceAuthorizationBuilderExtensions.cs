using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.DeviceAuthorization;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityDeviceAuthorizationBuilderExtensions
{
    /// <summary>
    /// Adds the transport-neutral, persistent device-authorization
    /// orchestration. A configured persistence provider must supply
    /// <see cref="IDeviceAuthorizationRequestStore{TProfile}"/> and session
    /// issuance must be enabled separately.
    /// </summary>
    public static IdentityBuilder<TProfile> AddDeviceAuthorization<TProfile>(
        this IdentityBuilder<TProfile> builder,
        Action<DeviceAuthorizationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new DeviceAuthorizationOptions();
        configure?.Invoke(options);

        builder.Services.RemoveAll<DeviceAuthorizationOptions>();
        builder.Services.AddSingleton(options);
        builder.Services.TryAddScoped<
            IIdentityDeviceAuthorizationService<TProfile>,
            IdentityDeviceAuthorizationService<TProfile>>();
        return builder;
    }
}
