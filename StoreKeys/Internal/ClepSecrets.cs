using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace StoreKeys.Internal;

/// <summary>
/// Unwraps the secrets a CLEP v4 state block carries.
/// </summary>
/// <remarks>
/// <c>ClepSignState</c>, <c>ClepHmacState</c> and <c>EncryptedDeviceKey</c> share an encoding: a
/// version, some encrypted payload, and an encrypted AES key schedule. The key that decrypts the
/// payload is recovered by XORing four words out of that schedule with fixed constants - the
/// same computation CikExtractor uses for the device key, applied to a different block.
/// </remarks>
internal static class ClepSecrets
{
    /// <summary>Layout of a ClepSignState block: version, then the key data, then the schedule.</summary>
    private const int KeyDataOffset = 4;
    private const int KeyDataSize = 544;
    private const int KeyScheduleOffset = KeyDataOffset + KeyDataSize;
    private const int KeyScheduleWords = 58;

    /// <summary>
    /// The RSA private key a provisioned device signs its authentication requests with, taken
    /// from the <c>ClepSignState</c> block of its device licence.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static RSA RsaSigningKey(byte[] clepSignState)
    {
        ArgumentNullException.ThrowIfNull(clepSignState);

        if (clepSignState.Length < KeyScheduleOffset + KeyScheduleWords * 4)
            throw new StoreKeysException(
                $"ClepSignState is {clepSignState.Length} bytes, too short to hold a key schedule.");

        var version = BinaryPrimitives.ReadUInt32LittleEndian(clepSignState);
        if (version != 4)
            throw new StoreKeysException($"Only version 4 ClepSignState is supported, got {version}.");

        var schedule = clepSignState.AsSpan(KeyScheduleOffset, KeyScheduleWords * 4);
        var blob = DecryptCbcZeroIv(schedule, clepSignState.AsSpan(KeyDataOffset, KeyDataSize));

        // The plaintext is a BCRYPT_RSAKEY_BLOB. CNG imports it directly, including the
        // RSAPRIVATE form that omits the private exponent.
        try
        {
            using var key = CngKey.Import(blob, CngKeyBlobFormat.GenericPrivateBlob);
            return new RSACng(key);
        }
        catch (CryptographicException ex)
        {
            var magic = BinaryPrimitives.ReadUInt32LittleEndian(blob);
            throw new StoreKeysException(
                $"ClepSignState did not decrypt to an importable RSA key (magic 0x{magic:X8}): {ex.Message}", ex);
        }
    }

    /// <summary>
    /// The 16-byte AES key a CLEP v4 block's payload is encrypted under, recovered from its
    /// encrypted key schedule.
    /// </summary>
    private static byte[] DecryptionKey(ReadOnlySpan<byte> keySchedule)
    {
        var words = MemoryMarshal.Cast<byte, uint>(keySchedule);

        var key = new byte[16];
        var target = MemoryMarshal.Cast<byte, uint>(key.AsSpan());

        target[0] = words[46] ^ words[56] ^ 0xE20DF371 ^ 0xCCB22FE6;
        target[1] = words[36] ^ words[47] ^ 0xDF080E39;
        target[2] = words[40] ^ words[51] ^ 0x6D09B2F5 ^ 0x2AE17AB9;
        target[3] = words[30] ^ words[41] ^ 0x37288CEC;

        return key;
    }

    /// <summary>AES-128-CBC with a zero IV, which is how these payloads are wrapped.</summary>
    private static byte[] DecryptCbcZeroIv(ReadOnlySpan<byte> keySchedule, ReadOnlySpan<byte> data)
    {
        using var aes = Aes.Create();
        aes.Key = DecryptionKey(keySchedule);
        aes.IV = new byte[16];

        return aes.DecryptCbc(data, aes.IV, PaddingMode.None);
    }
}
