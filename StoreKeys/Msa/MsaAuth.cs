using System.Text.Json.Serialization;

namespace StoreKeys.Msa;

/// <summary>
/// Constants and the cached-ticket shape for MSA licensing tokens. No OAuth flow on purpose:
/// the client id below is broker-only, so oauth20_authorize.srf rejects it with
/// unauthorized_client. Tokens come from the Web Account Manager - see <see cref="WamAuth"/>.
/// </summary>
internal static class MsaAuth
{
    /// <summary>The id LicenseManager.dll uses for its own token requests.</summary>
    public const string BrokerClientId = "268761a2-03f3-40df-8a8b-c3db24145b6b";

    public const string LicensingScope = "service::licensing.mp.microsoft.com::MBI_SSL";

    public sealed record Tokens(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("expires_in")] int ExpiresIn)
    {
        [JsonPropertyName("obtained_utc")]
        public DateTimeOffset ObtainedUtc { get; init; } = DateTimeOffset.UtcNow;

        [JsonIgnore]
        public bool IsExpired => DateTimeOffset.UtcNow >= ObtainedUtc.AddSeconds(ExpiresIn - 120);
    }
}
