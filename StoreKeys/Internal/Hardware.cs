using System.Management;
using System.Runtime.Versioning;
using System.Text;

namespace StoreKeys.Internal;

/// <summary>
/// The two hardware values a CLEP challenge is built from.
/// </summary>
/// <remarks>
/// This repeats what <c>CikExtractor.DeviceKeyParameters</c> does privately. Duplicated rather
/// than shared because that file is a verbatim upstream copy and editing it to widen visibility
/// would break the property that makes it diffable.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class Hardware
{
    /// <summary>
    /// The SMBIOS System (type 1) structure with its trailing string table, truncated to the
    /// 256 bytes a challenge carries.
    /// </summary>
    public static byte[] Smbios()
    {
        var scope = new ManagementScope(@"\\localhost\root\WMI");
        scope.Connect();

        using var searcher = new ManagementObjectSearcher(
            scope, new ObjectQuery("SELECT * FROM MSSmBios_RawSMBiosTables"));

        foreach (var entry in searcher.Get())
            if (entry?["SMBiosData"] is byte[] raw && SystemStructure(raw) is { } structure)
                return structure;

        throw new StoreKeysException("Could not read the SMBIOS System structure.");
    }

    /// <summary>Serial of PHYSICALDRIVE0, NUL-terminated and truncated to 64 bytes.</summary>
    public static byte[] DriveSerial()
    {
        using var searcher = new ManagementObjectSearcher(
            """SELECT * FROM Win32_DiskDrive WHERE DeviceID = "\\\\.\\PHYSICALDRIVE0" """);

        foreach (var entry in searcher.Get())
            if (entry["SerialNumber"] as string is { } serial)
            {
                var bytes = Encoding.UTF8.GetBytes(serial + '\0');
                return bytes.Length > ClepChallenge.DiskSerialSize
                    ? bytes[..ClepChallenge.DiskSerialSize]
                    : bytes;
            }

        throw new StoreKeysException("Could not read the serial of PHYSICALDRIVE0.");
    }

    /// <summary>
    /// Walks the SMBIOS tables for type 1 and returns it with the unformatted string section
    /// that follows, which is what the challenge expects.
    /// </summary>
    private static byte[]? SystemStructure(ReadOnlySpan<byte> smbios)
    {
        var current = 0;
        byte[]? system = null;

        while (current < smbios.Length)
        {
            if (smbios[current] == 0x1)
                system = smbios.Slice(current, smbios[current + 1]).ToArray();

            current += smbios[current + 1];

            var end = current;
            while (smbios[end] != 0x0 || smbios[end + 1] != 0x0)
                end++;
            end += 2;

            if (end - current != 0 && system is not null)
            {
                var strings = smbios[current..end];
                var combined = new byte[system.Length + strings.Length];

                system.CopyTo(combined, 0);
                strings.CopyTo(combined.AsSpan(system.Length));

                return combined.Length > ClepChallenge.SmbiosSize
                    ? combined[..ClepChallenge.SmbiosSize]
                    : combined;
            }

            current = end;
        }

        return null;
    }
}
