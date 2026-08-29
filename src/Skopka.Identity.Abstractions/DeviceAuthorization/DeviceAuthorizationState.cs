namespace Skopka.Identity.DeviceAuthorization;

public enum DeviceAuthorizationState
{
    Pending = 0,
    Approved = 1,
    Denied = 2,
    Consuming = 3,
    Consumed = 4,
    Expired = 5,
}
