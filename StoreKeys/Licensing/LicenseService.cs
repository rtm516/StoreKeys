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
    private const string RejectedTicket = "InvalidDeviceAuthorizationToken";

    /// <summary>The ticket the service last accepted, reused for subsequent calls.</summary>
    private static string? _acceptedTicket;

    public sealed record Result(int StatusCode, string RawBody, JsonNode? Json)
    {
        public bool IsSuccess => StatusCode is >= 200 and < 300;

        /// <summary>Status plus the inner fault, which is the part that says what to fix.</summary>
        public string Describe()
        {
            var inner = Json?["innererror"];
            var code = inner?["code"]?.GetValue<string>();

            return code is null ? $"HTTP {StatusCode}" : $"HTTP {StatusCode} {code}";
        }

        internal string? Fault => Json?["innererror"]?["code"]?.GetValue<string>();
    }

    public static async Task<Result> RequestAsync(Guid contentId, CancellationToken cancellationToken)
    {
        var userTicket = await WamAuth.GetTokenAsync();

        Result? last = null;

        foreach (var ticket in CandidateTickets())
        {
            var client = new LicensingClient(userTicket) { DeviceAuthorizationToken = ticket };

            var response = await client.RequestContentLicenseAsync(contentId, ct: cancellationToken);
            last = new Result(response.StatusCode, response.RawBody, response.Json);

            if (last.IsSuccess)
            {
                _acceptedTicket = ticket;
                return last;
            }

            if (last.Fault != RejectedTicket)
                return last;
        }

        return last ?? new Result(0, "", null);
    }

    /// <summary>Accepted ticket first, then everything Windows has cached for this user.</summary>
    private static IEnumerable<string> CandidateTickets()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        if (_acceptedTicket is not null && seen.Add(_acceptedTicket))
            yield return _acceptedTicket;

        foreach (var candidate in DeviceTokenStore.ReadAll())
            if (candidate.Token is not null && seen.Add(candidate.Token))
                yield return candidate.Token;
    }

}
