using Windows.Security.Authentication.OnlineId;

namespace StoreKeys.Msa
{
    internal static class SystemAuth
    {
        /// <summary>
        /// Device-ticket acquisition through the OnlineId System Authenticator.
        /// </summary>
        public static async Task<string> GetTicketAsync()
        {
            var authenticator = OnlineIdSystemAuthenticator.Default;
            authenticator.ApplicationId = new Guid(MsaAuth.BrokerClientId);

            var request = new OnlineIdServiceTicketRequest(MsaAuth.LicensingScope);
            var result = await authenticator.GetTicketAsync(request);

            if (result.Status != OnlineIdSystemTicketStatus.Success)
                throw new InvalidOperationException(Describe(result));

            return MsaAuth.StripTicketPrefix(result.Identity.Ticket.Value);
        }

        private static string Describe(OnlineIdSystemTicketResult result)
        {
            var error = result.ExtendedError;
            return error is null
                ? result.Status.ToString()
                : $"{result.Status} (0x{error.HResult:X8}) {error.Message}";
        }
    }
}
