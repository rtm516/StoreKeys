using System.Globalization;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace StoreKeys.Licensing;

/// <summary>
/// Client for the Microsoft Store licensing service.
///
/// The body matches a captured, successful (HTTP 200) request from Xbox GamingServices field for
/// field. Several parts of it are not what LicenseManager.dll's strings suggest:
///
///   * Authorization is a bare "t=&lt;ticket&gt;", not WLID1.0="..."
///   * licenseVersion is 4, not 7
///   * keyOnly accompanies needKey
///   * deviceContext carries three fields, all literally "Public"
///   * clientChallenge is mandatory, and a missing one and a malformed one both give faultcode
///     3023 DeviceEkbRequired - so that error does not distinguish them
///
/// The call comes from XboxLicenseManager (XboxLm), not ClipSVC.
/// </summary>
internal sealed class LicensingClient(string accessToken)
{
    public const string BaseAddress = "https://licensing.mp.microsoft.com";
    public const string ContentRoute = "/v7.0/licenses/content";

    /// <summary>User-agent of the component that legitimately makes this call.</summary>
    private const string UserAgent =
        "XboxLm-PC/Microsoft.GamingServices_38.117.15001.0_x64__8wekyb3d8bbwe";

    private static readonly HttpClient Http = new() { BaseAddress = new Uri(BaseAddress) };
    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    public sealed record Response(int StatusCode, string RawBody, JsonNode? Json)
    {
        public bool IsSuccess => StatusCode is >= 200 and < 300;
    }

    /// <summary>
    /// Base64 clientChallenge. Defaults to a generated one - it is a static protocol version
    /// declaration, not a credential, so it never needs to come from a capture.
    /// </summary>
    public string ClientChallenge { get; set; } = Licensing.ClientChallenge.Build();

    /// <summary>
    /// The Device Authorization token for the Authorization header. This is NOT the user ticket:
    /// the service distinguishes them, and supplying a user ticket here yields
    /// faultcode 4000 InvalidDeviceAuthorizationToken. The user identity travels in the body as
    /// users[sid][].identityValue instead. Leave null to fall back to the user ticket.
    /// </summary>
    public string? DeviceAuthorizationToken { get; set; }

    public async Task<Response> RequestContentLicenseAsync(
        Guid contentId,
        bool needKey = true,
        string? market = null,
        CancellationToken ct = default)
    {
        var body = BuildRequestBody(contentId, needKey, market);
        return await PostAsync(ContentRoute, body, ct);
    }

    public JsonObject BuildRequestBody(Guid contentId, bool needKey, string? market)
    {
        return new JsonObject
        {
            ["clientChallenge"] = ClientChallenge,
            ["contentId"] = contentId.ToString().ToUpperInvariant(),
            ["deviceContext"] = new JsonObject
            {
                ["hardwareManufacturer"] = "Public",
                ["hardwareType"] = "Public",
                ["mobileOperator"] = "Public",
            },
            ["keyOnly"] = true,
            ["licenseVersion"] = 4,
            ["market"] = market ?? CurrentMarket(),
            ["needKey"] = needKey,
            ["users"] = new JsonObject
            {
                [CurrentUserSid()] = new JsonArray
                {
                    new JsonObject
                    {
                        ["identityType"] = "Msa",
                        ["identityValue"] = accessToken,
                        ["localTicketReference"] = TicketReference,
                    },
                },
            },
        };
    }

    private static string CurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();

        return identity.User?.Value
               ?? throw new StoreKeysException("Could not determine the current user's SID.");
    }

    public async Task<Response> PostAsync(string route, JsonObject body, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, route)
        {
            Content = new StringContent(body.ToJsonString(Pretty), Encoding.UTF8, "application/json"),
        };

        request.Headers.TryAddWithoutValidation(
            "Authorization", $"t={DeviceAuthorizationToken ?? accessToken}");
        request.Headers.TryAddWithoutValidation("from", "XboxLicenseManager");
        request.Headers.TryAddWithoutValidation("x-xbl-contract-version", "2");
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
        request.Headers.TryAddWithoutValidation("MS-CV", CorrelationVector());

        using var response = await Http.SendAsync(request, ct);
        var raw = await response.Content.ReadAsStringAsync(ct);

        JsonNode? parsed = null;
        try { parsed = JsonNode.Parse(raw); } catch { /* keep raw for diagnosis */ }

        return new Response((int)response.StatusCode, raw, parsed);
    }

    /// <summary>Correlates the single identity we send; the value itself is not inspected.</summary>
    private const string TicketReference = "1";

    private static string CurrentMarket()
    {
        try { return RegionInfo.CurrentRegion.TwoLetterISORegionName; }
        catch { return "US"; }
    }

    private static string CorrelationVector()
        => Convert.ToBase64String(Guid.NewGuid().ToByteArray())[..16].Replace('/', 'a') + ".0";
}
