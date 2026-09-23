using System.Globalization;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using StoreKeys.Msa;

namespace StoreKeys.Licensing;

/// <summary>
/// Client for the Microsoft Store licensing service.
///
/// Parts of the contract that are easy to get wrong:
///
///   * Authorization is a bare "t=&lt;ticket&gt;"
///   * licenseVersion is 4
///   * keyOnly accompanies needKey
///   * deviceContext carries three fields, all literally "Public"
///   * clientChallenge is mandatory, and a missing one and a malformed one both give faultcode
///     3023 DeviceEkbRequired - so that error does not distinguish them
///
/// The call comes from XboxLicenseManager (XboxLm), not ClipSVC.
/// </summary>
/// <param name="userTicket">MSA user ticket, which proves entitlement.</param>
/// <param name="deviceToken">
/// Device Authorization token for the Authorization header. Not interchangeable with the user
/// ticket: sending one of those here gives faultcode 4000 InvalidDeviceAuthorizationToken.
/// </param>
internal sealed class LicensingClient(string userTicket, string deviceToken)
{
    private const string BaseAddress = "https://licensing.mp.microsoft.com";
    private const string ContentRoute = "/v7.0/licenses/content";

    /// <summary>User-agent of the component that legitimately makes this call.</summary>
    private const string UserAgent =
        "XboxLm-PC/Microsoft.GamingServices_38.117.15001.0_x64__8wekyb3d8bbwe";

    /// <summary>Correlates the single identity we send; the value itself is not inspected.</summary>
    private const string TicketReference = "1";

    private static readonly HttpClient Http = new() { BaseAddress = new Uri(BaseAddress) };
    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    public sealed record Response(int StatusCode, string RawBody, JsonNode? Json)
    {
        public bool IsSuccess => StatusCode is >= 200 and < 300;
    }

    public async Task<Response> RequestContentLicenseAsync(Guid contentId, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, ContentRoute)
        {
            Content = new StringContent(
                BuildRequestBody(contentId).ToJsonString(Pretty), Encoding.UTF8, "application/json"),
        };

        request.Headers.TryAddWithoutValidation("Authorization", $"{MsaAuth.TicketPrefix}{deviceToken}");
        request.Headers.TryAddWithoutValidation("from", "XboxLicenseManager");
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
        request.Headers.TryAddWithoutValidation("MS-CV", CorrelationVector());

        using var response = await Http.SendAsync(request, ct);
        var raw = await response.Content.ReadAsStringAsync(ct);

        JsonNode? parsed = null;
        try { parsed = JsonNode.Parse(raw); } catch { /* keep raw for diagnosis */ }

        return new Response((int)response.StatusCode, raw, parsed);
    }

    private JsonObject BuildRequestBody(Guid contentId)
    {
        return new JsonObject
        {
            ["clientChallenge"] = ClientChallenge.Build(),
            ["contentId"] = contentId.ToString().ToUpperInvariant(),
            ["deviceContext"] = new JsonObject
            {
                ["hardwareManufacturer"] = "Public",
                ["hardwareType"] = "Public",
                ["mobileOperator"] = "Public",
            },
            ["keyOnly"] = true,
            ["licenseVersion"] = 4,
            ["market"] = CurrentMarket(),
            ["needKey"] = true,
            ["users"] = new JsonObject
            {
                [CurrentUserSid()] = new JsonArray
                {
                    new JsonObject
                    {
                        ["identityType"] = "Msa",
                        ["identityValue"] = userTicket,
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

    private static string CurrentMarket()
    {
        try { return RegionInfo.CurrentRegion.TwoLetterISORegionName; }
        catch { return "US"; }
    }

    private static string CorrelationVector()
        => Convert.ToBase64String(Guid.NewGuid().ToByteArray())[..16].Replace('/', 'a') + ".0";
}
