namespace StoreKeys;

/// <summary>
/// An unwrapped content key (CIK) and the ids it is addressable by. A packed licence entry
/// carries two GUIDs for the same key and an XVC header may reference either, so both are kept.
/// </summary>
public sealed record ContentKey(IReadOnlyList<Guid> KeyIds, byte[] Key)
{
    /// <summary>Size of a .cik file: a 16-byte key id followed by the 32-byte key.</summary>
    public const int CikFileSize = 0x30;

    /// <summary>The primary key id, which is what XvdTool.Streaming looks a key up by.</summary>
    public Guid KeyId => KeyIds[0];

    /// <summary>Returns the key as a hexadecimal string.</summary>
    public string ToHexString() => Convert.ToHexString(Key);

    /// <summary>
    /// The 48-byte .cik representation for one of this key's ids, in the layout
    /// XvdTool.Streaming expects.
    /// </summary>
    public byte[] ToCikFile(Guid keyId)
    {
        if (!KeyIds.Contains(keyId))
            throw new ArgumentException($"{keyId} is not an id of this key.", nameof(keyId));

        var buffer = new byte[CikFileSize];
        keyId.TryWriteBytes(buffer.AsSpan(0, 16));
        Key.CopyTo(buffer.AsSpan(16));

        return buffer;
    }

    /// <summary>Every (id, file bytes) pair, for callers writing one file per id.</summary>
    public IEnumerable<(Guid KeyId, byte[] Contents)> ToCikFiles()
        => KeyIds.Select(id => (id, ToCikFile(id)));
}
