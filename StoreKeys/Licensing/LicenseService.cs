using System.Text.Json.Nodes;
using StoreKeys.Msa;

namespace StoreKeys.Licensing;

/// <summary>
/// Requests content licences from the Store licensing service.
/// </summary>
/// <remarks>
/// The Authorization header needs a *device* ticket, not a user one. WAM only ever returns user
/// tickets, so this machine's device ticket comes from the OnlineId system authenticator instead
/// - see <see cref="SystemAuth"/>.
/// </remarks>
internal static class LicenseService
{
    public sealed record Result(int StatusCode, string RawBody, JsonNode? Json)
    {
        public bool IsSuccess => StatusCode is >= 200 and < 300;

        /// <summary>
        /// The reason the service gave for not satisfying the request. Part of the licence
        /// contract alongside keys and leases, but not something we have seen returned, so the
        /// wording of a real one is unknown.
        /// </summary>
        public string? SatisfactionFailure =>
            Json?["license"]?["satisfactionFailure"]?["description"]?.GetValue<string>();

        /// <summary>Status plus the inner fault, which is the part that says what to fix.</summary>
        public string Describe()
        {
            if (SatisfactionFailure is { } reason)
                return $"not entitled ({reason})";

            var inner = Json?["innererror"];
            var code = inner?["code"]?.GetValue<string>();

            return code is null ? $"HTTP {StatusCode}" : $"HTTP {StatusCode} {code}";
        }

        internal string? Fault => Json?["innererror"]?["code"]?.GetValue<string>();
    }

    /// <param name="contentId">Content to request a licence for.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <param name="deviceToken">
    /// A device token to use instead of this machine's. Supplied when the identity was
    /// provisioned, since only its own token pairs with its device key.
    /// </param>
    public static async Task<Result> RequestAsync(
        Guid contentId,
        CancellationToken cancellationToken,
        string? deviceToken = null)
    {
        var userTicket = await WamAuth.GetTokenAsync();
        deviceToken ??= await SystemAuth.GetTicketAsync();

        var client = new LicensingClient(userTicket, deviceToken);
        var response = await client.RequestContentLicenseAsync(contentId, cancellationToken);

        return new Result(response.StatusCode, response.RawBody, response.Json);
    }
}
