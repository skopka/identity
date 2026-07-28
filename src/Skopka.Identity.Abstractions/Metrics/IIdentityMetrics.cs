namespace Skopka.Identity.Metrics;

public interface IIdentityMetrics
{
    IIdentityOpScope Begin(string operation);
}