using CikExtractor;

namespace StoreKeys;

/// <summary>This machine's device key, which unwraps every CIK the service issues to it.</summary>
public static class DeviceKey
{
    /// <summary>Length of a device key, in bytes.</summary>
    public const int Size = 0x10;

    /// <summary>
    /// Derives the device key. Prompts for elevation, because it reads the licence store out of
    /// the registry. Stable for the life of the Windows install, so derive it once and cache it.
    /// </summary>
    public static byte[] Derive()
    {
        var manager = new RegistryManager();

        // Exports the hive itself, which is the elevation prompt.
        if (!manager.LoadLicenses())
            throw new StoreKeysException(
                "Could not read the licence store. This needs an elevated 'reg save', so it "
                + "fails if the elevation prompt is declined.");

        var parameters = DeviceKeyParameters.DumpParameters(manager)
                         ?? throw new StoreKeysException(
                             "No usable device licence found, so the device key cannot be derived.");

        return DeviceKeyDumper.DeriveDeviceKey(parameters);
    }

    /// <summary>Parses a 32-character hex device key.</summary>
    public static byte[] Parse(string hex)
    {
        var key = Convert.FromHexString(hex.Trim());

        return key.Length == Size
            ? key
            : throw new ArgumentException($"A device key is {Size} bytes, got {key.Length}.", nameof(hex));
    }
}
