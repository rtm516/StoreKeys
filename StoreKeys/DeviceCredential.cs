using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using CikExtractor.Models;

namespace StoreKeys;

/// <summary>
/// A device identity: the device key, plus whatever is needed to obtain a matching device
/// token. This is the unit worth caching between runs.
/// </summary>
/// <remarks>
/// The key and the token have to come from the same device identity - the licensing service
/// wraps the CIK under the key belonging to whichever device authenticated the request - so they
/// travel together rather than being passed around separately.
///
/// Note what is deliberately absent: the device token itself. It expires within hours, so what
/// is stored is the material needed to mint a fresh one.
///
/// Nothing here touches the disk. <see cref="ToJson"/> and <see cref="FromJson"/> exist so the
/// caller can persist it wherever it wants.
/// </remarks>
public sealed record DeviceCredential
{
    /// <summary>
    /// The device key as hex, when it was derived up front. Null for a provisioned identity,
    /// whose key comes from <see cref="DeviceLicense"/> on demand.
    /// </summary>
    [JsonPropertyName("deviceKey")]
    public string? DeviceKeyHex { get; init; }

    /// <summary>
    /// Membername of a provisioned device credential. Null for the local machine's identity,
    /// whose device token comes from the OS rather than being minted by us.
    /// </summary>
    [JsonPropertyName("membername")]
    public string? Membername { get; init; }

    /// <summary>Password of a provisioned device credential.</summary>
    [JsonPropertyName("password")]
    public string? Password { get; init; }

    /// <summary>Base64 SPLicenseBlock issued when the device was provisioned.</summary>
    [JsonPropertyName("deviceLicense")]
    public string? DeviceLicense { get; init; }

    /// <summary>When this credential was created.</summary>
    [JsonPropertyName("createdUtc")]
    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// The device key. Derived from <see cref="DeviceLicense"/> when it was not stored directly,
    /// which is why this can throw: a licence the derivation does not support (anything but CLEP
    /// v4) only fails at this point, after the credential itself is safely in hand.
    /// </summary>
    [JsonIgnore]
    public byte[] DeviceKey
    {
        get
        {
            if (DeviceKeyHex is not null)
                return StoreKeys.DeviceKey.Parse(DeviceKeyHex);

            if (DeviceLicense is null)
                throw new StoreKeysException("This credential carries neither a device key nor a licence.");

            var licence = new SpLicense(Convert.FromBase64String(DeviceLicense));

            return licence.EncryptedDeviceKey is { } encrypted
                ? StoreKeys.DeviceKey.FromDeviceLicense(encrypted)
                : throw new StoreKeysException("This licence carries no EncryptedDeviceKey block.");
        }
    }

    /// <summary>
    /// CLEP version of the stored device licence, or null when there is no licence. Only
    /// version 4 can be derived from; the service issues 2 when the challenge is absent.
    /// </summary>
    [JsonIgnore]
    public uint? DeviceLicenseVersion
    {
        get
        {
            if (DeviceLicense is null)
                return null;

            var block = new SpLicense(Convert.FromBase64String(DeviceLicense)).EncryptedDeviceKey;

            return block is { Length: >= 4 }
                ? BinaryPrimitives.ReadUInt32LittleEndian(block)
                : null;
        }
    }

    /// <summary>
    /// True when this identity was provisioned by us, and so carries the material to mint its
    /// own device token. False for the local machine's identity, whose token the OS holds.
    /// </summary>
    [JsonIgnore]
    public bool IsProvisioned => Membername is not null && DeviceLicense is not null;

    /// <summary>
    /// This machine's identity, derived from the local licence store. Prompts for elevation.
    /// </summary>
    public static DeviceCredential FromLocalMachine()
        => new() { DeviceKeyHex = Convert.ToHexString(StoreKeys.DeviceKey.Derive()) };

    /// <summary>
    /// Registers a new device identity with MSA. No elevation and no registry read, so this
    /// works without admin rights.
    /// </summary>
    /// <remarks>
    /// This writes to Microsoft's identity service: it creates a device registration under a
    /// generated membername and password. Provision once and cache the result - the returned
    /// credential is everything needed to reuse the identity.
    ///
    /// The key is not derived here. Whether the issued licence is one we can derive from is only
    /// discovered by reading <see cref="DeviceKey"/>, deliberately, so that a registration is
    /// never lost to a derivation failure.
    /// </remarks>
    public static async Task<DeviceCredential> ProvisionAsync(
        HttpClient? http = null,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            throw new StoreKeysException("Provisioning reads local hardware, so it needs Windows.");

        var client = http ?? new HttpClient();

        try
        {
            var result = await Msa.DeviceProvisioning.ProvisionAsync(client, cancellationToken);

            return new DeviceCredential
            {
                Membername = result.Membername,
                Password = result.Password,
                DeviceLicense = result.DeviceLicense,
            };
        }
        finally
        {
            if (http is null) client.Dispose();
        }
    }

    /// <summary>Serialises this credential. The result contains secrets; store it accordingly.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    /// <summary>Reads a credential back.</summary>
    public static DeviceCredential FromJson(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        var credential = JsonSerializer.Deserialize<DeviceCredential>(json, JsonOptions)
                         ?? throw new StoreKeysException("Device credential JSON was empty.");

        if (credential.DeviceKeyHex is null && credential.DeviceLicense is null)
            throw new StoreKeysException("Device credential has neither a device key nor a licence.");

        return credential;
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
