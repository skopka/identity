namespace Skopka.Identity.Metrics;

public interface IIdentityOpScope : IDisposable { void Success(); void Failure(string errorCode); }