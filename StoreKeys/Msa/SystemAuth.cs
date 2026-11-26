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
            authenticator.ApplicationId = new Guid("268761a2-03f3-40df-8a8b-c3db24145b6b");

            var request = new OnlineIdServiceTicketRequest("service::licensing.mp.microsoft.com::MBI_SSL");
            var result = await authenticator.GetTicketAsync(request);

            if (result.Status != OnlineIdSystemTicketStatus.Success)
                throw new InvalidOperationException(Describe(result));

            var ticket = result.Identity.Ticket.Value;
            return ticket.StartsWith("t=", StringComparison.Ordinal)
                ? ticket[2..]
                : ticket;
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
