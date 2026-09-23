using System.Text.Json.Nodes;
using StoreKeys.Msa;

namespace StoreKeys.Licensing;

/// <summary>
/// Requests content licences from the Store licensing service, handling device-ticket
/// selection.
/// </summary>
/// <remarks>
/// The Authorization header needs a *device* ticket, not a user one. We cannot mint one - WAM
/// returns user tickets for every client id, scope policy and request property - but Windows
/// caches device tickets for this user, so we read those.
///
/// Which cached ticket the service accepts is scoped per relying party and is not predictable
/// from the key name, so they are tried in order until one is accepted. Only a rejected ticket
/// is worth retrying; any other fault means the request itself is wrong.
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
    /// A device token to use instead of searching the machine's cached ones. Supplied when the
    /// identity was provisioned, since only its own token pairs with its device key.
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
