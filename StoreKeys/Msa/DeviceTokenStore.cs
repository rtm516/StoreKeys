using System.Security.Cryptography;
using System.Text;

namespace StoreKeys.Msa;

/// <summary>
/// Reads this machine's MSA Device Authorization token out of the current user's own token
/// store, so the online path needs no traffic capture.
///
/// The licensing service wants a *device* ticket in the Authorization header - a user ticket
/// gets faultcode 4000 InvalidDeviceAuthorizationToken - and WAM will not issue one. Windows
/// caches them anyway: per yegors/deGDID (https://github.com/yegors/deGDID), MSA keeps
/// per-client device tickets under IdentityCRL, keyed by client id or calling package SID.
///
/// The user's own hive, own DPAPI key, own device; nothing elevated.
/// </summary>
internal static class DeviceTokenStore
{
    private const string TokenRoot = @"SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token";

    // Deliberately no preferred client id or package SID. Which ticket the service accepts is
    // scoped per relying party and is not predictable from the key name - the SIDs hardcoded in
    // LicenseManager.dll are rejected, as is the dcat client WUTokenHelper uses. Callers try
    // these in order, so ordering affects only the cost of the first run, never success.

    /// <summary>
    /// One entry per key holding a DeviceTicket. Failures are reported rather than skipped:
    /// "nothing found" and "found but could not decrypt" need very different fixes, and
    /// silently dropping the second looks exactly like the first.
    /// </summary>
    public sealed record Candidate(
        string Source,
        string? DeviceId,
        int ProtectedBytes,
        string? Token,
        string Status)
    {
        /// <summary>
        /// Every long printable run found in the decrypted blob, longest first. A blob can hold
        /// more than one ticket, so when the chosen one is rejected the alternatives are the
        /// first thing to look at.
        /// </summary>
        public IReadOnlyList<string> Alternatives { get; init; } = [];


        /// <summary>Device tickets observed from the OS are ~1871 chars and start "EwB".</summary>
        public bool LooksLikeDeviceToken =>
            Token is not null
            && (Token.StartsWith("EwB", StringComparison.Ordinal) || Token.Length is > 1700 and < 2200);
    }

    public static List<Candidate> ReadAll()
    {
        var candidates = new List<Candidate>();

        using var root = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(TokenRoot);
        if (root is null)
            return candidates;

        foreach (var name in root.GetSubKeyNames())
        {
            using var key = root.OpenSubKey(name);
            if (key is null) continue;

            var raw = key.GetValue("DeviceTicket");
            if (raw is null) continue;

            var deviceId = key.GetValue("DeviceId") as string;

            if (raw is not byte[] blob || blob.Length == 0)
            {
                candidates.Add(new Candidate(name, deviceId, 0, null,
                    $"DeviceTicket is {raw.GetType().Name}, not binary"));
                continue;
            }

            var (token, status, alternatives) = Unwrap(blob);
            candidates.Add(new Candidate(name, deviceId, blob.Length, token, status)
            {
                Alternatives = alternatives,
            });
        }

        // Ordered by shape alone, which is machine-agnostic: readable first, then anything the
        // size and marker suggest is a device ticket, then longest.
        return candidates
            .OrderByDescending(c => c.Token is not null)
            .ThenByDescending(c => c.LooksLikeDeviceToken)
            .ThenByDescending(c => c.Token?.Length ?? 0)
            .ToList();
    }

    private static Candidate? _cachedBest;
    private static bool _cacheLoaded;

    /// <summary>
    /// Best readable ticket, cached. Reading means DPAPI-decrypting every entry, so callers
    /// that only need to know whether one exists should not pay for that twice.
    /// </summary>
    public static Candidate? ReadBest()
    {
        if (_cacheLoaded)
            return _cachedBest;

        _cachedBest = ReadAll().FirstOrDefault(c => c.Token is not null);
        _cacheLoaded = true;

        return _cachedBest;
    }

    /// <summary>
    /// Tries the plausible shapes in turn. The blob may not be DPAPI at all, and if it is it
    /// may be scoped to the machine rather than the user, so neither is assumed.
    /// </summary>
    private static (string? Token, string Status, IReadOnlyList<string> Alternatives) Unwrap(byte[] blob)
    {
        var start = FindDpapiStart(blob);

        if (start < 0)
            return Decode(blob) is { } plain
                ? (plain, "plaintext", Runs(blob))
                : (null, $"not DPAPI and not decodable text ({blob.Length} bytes)", []);

        // MSA prefixes its own dword before the DPAPI blob, so the payload rarely begins at 0.
        var payload = start == 0 ? blob : blob[start..];

        foreach (var scope in new[] { DataProtectionScope.CurrentUser, DataProtectionScope.LocalMachine })
        {
            try
            {
                var plain = ProtectedData.Unprotect(payload, null, scope);
                return Decode(plain) is { } text
                    ? (text, $"dpapi@{start}/{scope}", Runs(plain))
                    : (null, $"dpapi@{start}/{scope} decrypted to {plain.Length} undecodable bytes", Runs(plain));
            }
            catch (CryptographicException)
            {
                // Try the next scope; report below if none work.
            }
        }

        return (null, $"DPAPI blob at offset {start} but decrypt failed for both scopes "
                      + "(likely protected with caller-supplied entropy)", []);
    }

    /// <summary>
    /// Offset of the DPAPI blob, found by locating the provider GUID
    /// {df9d8cd0-1501-11d1-8c7a-00c04fc297eb} and stepping back over the version dword that
    /// precedes it. Searching rather than assuming offset 0, because these values carry a
    /// leading dword of their own. Returns -1 when the blob is not DPAPI.
    /// </summary>
    private static int FindDpapiStart(byte[] blob)
    {
        ReadOnlySpan<byte> providerGuid =
        [
            0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11,
            0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB,
        ];

        // Only look at the very start; a match deeper in is coincidence, not a header.
        var limit = Math.Min(blob.Length - providerGuid.Length, 64);

        for (var i = 4; i <= limit; i++)
            if (blob.AsSpan(i, providerGuid.Length).SequenceEqual(providerGuid))
                return i - 4;

        return -1;
    }

    /// <summary>
    /// Pulls the ticket out of the decrypted blob. The plaintext is a structure, not a bare
    /// string, so rather than model it we find the long printable run inside: MSA tickets are
    /// query-string shaped ("t=Ew...&amp;p=") and nothing else in the blob resembles that.
    /// </summary>
    private static string? Decode(byte[] plain)
    {
        if (plain.Length == 0) return null;

        // Try UTF-16LE first - that is how MSA stores these - then UTF-8.
        foreach (var encoding in new[] { Encoding.Unicode, Encoding.UTF8 })
        {
            if (ExtractTicket(encoding.GetString(plain)) is { } ticket)
                return ticket;
        }

        return null;
    }

    /// <summary>
    /// Long printable runs in a blob, across both encodings, longest first. Deduplicated
    /// because a UTF-16LE payload also yields partial hits when read as UTF-8.
    /// </summary>
    private static IReadOnlyList<string> Runs(byte[] plain)
        => new[] { Encoding.Unicode, Encoding.UTF8 }
            .SelectMany(e => RunsIn(e.GetString(plain)))
            .Distinct()
            .OrderByDescending(r => r.Length)
            .Take(6)
            .ToList();

    private static List<string> RunsIn(string text)
        => System.Text.RegularExpressions.Regex
            .Matches(text, "[A-Za-z0-9+/=_\\-&%.:*!]{200,}")
            .Select(m => m.Value)
            .ToList();

    /// <summary>Longest plausible ticket run in a decoded string, or null.</summary>
    private static string? ExtractTicket(string text)
    {
        // Ticket alphabet: base64url plus the '&', '=' and '%' of the query-string wrapper.
        var runs = RunsIn(text);

        if (runs.Count == 0) return null;

        // "Ew" is the MSA compact-token marker; prefer a run that actually looks like one.
        var ticket = runs
            .OrderByDescending(r => r.Contains("Ew", StringComparison.Ordinal))
            .ThenByDescending(r => r.Length)
            .First();

        // Stored tickets keep their "t=" prefix, but the Authorization header is built as
        // "t={token}" - returning it with the prefix intact would send "t=t=Ew...".
        return MsaAuth.StripTicketPrefix(ticket);
    }
}
