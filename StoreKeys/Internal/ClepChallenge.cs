using System.Buffers.Binary;
using System.Numerics;

namespace StoreKeys.Internal;

/// <summary>
/// Builds the CLEP licence challenges that MSA device provisioning expects as components
/// 8196 (v2) and 8197 (v4). Without them the service issues a v2 device licence, whose
/// device key nobody has worked out how to derive.
/// </summary>
/// <remarks>
/// The obfuscation is a bespoke Feistel cipher keyed off a single constant, so there is no
/// library for it. Ported from xodus (GPL-3.0) and checked against vectors generated from it.
/// </remarks>
internal static class ClepChallenge
{
    public const int SmbiosSize = 256;
    public const int DiskSerialSize = 64;
    public const int ChallengeSize = 2048;

    /// <summary>Builds the (v2, v4) challenge buffers for this machine's hardware.</summary>
    public static (byte[] V2, byte[] V4) Build(ReadOnlySpan<byte> smbios, ReadOnlySpan<byte> diskSerial)
    {
        if (smbios.Length > SmbiosSize)
            throw new ArgumentException($"SMBIOS is at most {SmbiosSize} bytes.", nameof(smbios));
        if (diskSerial.Length > DiskSerialSize)
            throw new ArgumentException($"Drive serial is at most {DiskSerialSize} bytes.", nameof(diskSerial));

        // Both layouts are 2048 bytes and start with version, SMBIOS, drive serial. Everything
        // else - TPM areas, escrowed keys, reserved - stays zero.
        var v2 = new byte[ChallengeSize];
        BinaryPrimitives.WriteUInt32LittleEndian(v2, 2);
        smbios.CopyTo(v2.AsSpan(4));
        diskSerial.CopyTo(v2.AsSpan(260));
        v2[328] = 1;                       // always_1

        var v4 = new byte[ChallengeSize];
        BinaryPrimitives.WriteUInt32LittleEndian(v4, 4);
        smbios.CopyTo(v4.AsSpan(4));
        diskSerial.CopyTo(v4.AsSpan(260));
        BinaryPrimitives.WriteUInt32LittleEndian(v4.AsSpan(1231), 1);   // debugger_not_present

        Obfuscate(v2);
        Obfuscate(v4);

        return (v2, v4);
    }

    /// <summary>
    /// Encrypts the buffer in place: the second word of block 0 seeds the IV and is replaced by
    /// the initial cipher state, then the remaining 255 blocks run through in CBC-like mode.
    /// </summary>
    private static void Obfuscate(byte[] buffer)
    {
        var iv = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(4, 4));
        var cipher = new Cipher(iv);

        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(4, 4), cipher.Lo);

        for (var offset = 8; offset < ChallengeSize; offset += 8)
        {
            var span = buffer.AsSpan(offset, 8);
            var block = BinaryPrimitives.ReadUInt64LittleEndian(span);
            BinaryPrimitives.WriteUInt64LittleEndian(span, cipher.Encrypt(block));
        }
    }

    private struct Cipher
    {
        private const uint MagicLo = 0x41393243;
        private const uint MagicHi = 0x24181621;
        private const uint Magic01 = 0x2418;
        private const uint Magic02 = 0x1621;
        private const uint Magic03 = 0x4139;
        private const uint Magic04 = 0x3243;

        public static readonly uint InitialState = ComputeInitialState();

        public uint Lo;
        private uint _hi;
        private ulong _plain;

        public Cipher(uint iv)
        {
            Lo = InitialState ^ iv;
            _hi = 0;
            _plain = iv;
        }

        // The eight round functions. The key schedule walks them forwards; the cipher walks the
        // same functions backwards.
        private static uint Round1(uint x) => unchecked(Magic04 * RotR(x ^ MagicHi, 22) - RotR(x, 8));
        private static uint Round2(uint x) => unchecked(Magic04 * (RotR(x, 15) ^ Magic01));
        private static uint Round3(uint x) => unchecked((x >> 9) + Magic02 * RotL(x ^ Magic03, 3));
        private static uint Round4(uint x) => unchecked(RotR(x, 28) ^ (Magic03 * RotR(x ^ MagicHi, 9)));
        private static uint Round5(uint x) => unchecked(RotR(x, 12) + Magic04 * RotR(x - MagicHi, 14));
        private static uint Round6(uint x) => unchecked(RotR(x, 11) ^ (Magic01 * RotL(x ^ Magic02, 2)));
        private static uint Round7(uint x) => unchecked(x - MagicLo - Magic02);
        private static uint Round8(uint x) => unchecked(Magic03 * RotL(x ^ Magic01, 2) - RotR(x, 18));

        // Used only by the block function: Round0 seeds, Whiten produces the output word.
        private static uint Round0(uint x) => unchecked(Magic04 * RotR(x - MagicHi, 18) - RotR(x, 9));
        private static uint Whiten(uint x) => unchecked(Magic03 * RotR(x + MagicHi, 10) - RotR(x, 29));

        /// <summary>(a, b) -> (b, a ^ round(b)) through rounds 1..8.</summary>
        private static (uint A, uint B) RunRounds(uint a, uint b)
        {
            (a, b) = (b, a ^ Round1(b));
            (a, b) = (b, a ^ Round2(b));
            (a, b) = (b, a ^ Round3(b));
            (a, b) = (b, a ^ Round4(b));
            (a, b) = (b, a ^ Round5(b));
            (a, b) = (b, a ^ Round6(b));
            (a, b) = (b, a ^ Round7(b));
            (a, b) = (b, a ^ Round8(b));
            return (a, b);
        }

        /// <summary>(a, b) -> (b ^ round(a), a) through rounds 8..1.</summary>
        private static (uint A, uint B) RunRoundsInverse(uint a, uint b)
        {
            (a, b) = (b ^ Round8(a), a);
            (a, b) = (b ^ Round7(a), a);
            (a, b) = (b ^ Round6(a), a);
            (a, b) = (b ^ Round5(a), a);
            (a, b) = (b ^ Round4(a), a);
            (a, b) = (b ^ Round3(a), a);
            (a, b) = (b ^ Round2(a), a);
            (a, b) = (b ^ Round1(a), a);
            return (a, b);
        }

        private static uint ComputeInitialState()
        {
            var k0 = unchecked(~(Magic03 * RotR(MagicHi, 10)));
            var (_, k8) = RunRounds(0, k0);
            return k8;
        }

        public ulong Encrypt(ulong block)
        {
            var blockLo = (uint)block;
            var blockHi = (uint)(block >> 32);
            var plainLo = (uint)_plain;
            var plainHi = (uint)(_plain >> 32);

            var r0 = Lo ^ blockLo;
            var r1 = _hi ^ blockHi ^ Round0(r0);
            var (r8, r9) = RunRoundsInverse(r0, r1);

            var newLo = plainLo ^ r8 ^ Whiten(r9);
            var newHi = r9 ^ plainHi;

            Lo = newLo;
            _hi = newHi;
            _plain = block;

            return newLo | ((ulong)newHi << 32);
        }

        public ulong Decrypt(ulong block)
        {
            var newLo = (uint)block;
            var newHi = (uint)(block >> 32);
            var oldLo = Lo;
            var oldHi = _hi;
            var plainLo = (uint)_plain;
            var plainHi = (uint)(_plain >> 32);

            var r9 = newHi ^ plainHi;
            var r8 = newLo ^ plainLo ^ Whiten(r9);

            var (r0, r1) = RunRounds(r8, r9);

            var blockLo = oldLo ^ r0;
            var blockHi = oldHi ^ r1 ^ Round0(r0);
            var plain = blockLo | ((ulong)blockHi << 32);

            Lo = newLo;
            _hi = newHi;
            _plain = plain;

            return plain;
        }

        private static uint RotR(uint value, int count) => BitOperations.RotateRight(value, count);
        private static uint RotL(uint value, int count) => BitOperations.RotateLeft(value, count);
    }
}
