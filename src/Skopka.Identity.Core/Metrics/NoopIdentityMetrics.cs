namespace Skopka.Identity.Metrics;

public sealed class NoopIdentityMetrics : IIdentityMetrics
{
    private sealed class Scope : IDisposable { public void Dispose() { } }
    public IIdentityOpScope Begin(string operation)
    {
        throw new NotImplementedException();
    }
}