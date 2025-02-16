using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace Chnkd;

// DAREv1 is insecure because a) the stream can be truncated and b) chunks can be swapped between streams with key reuse
// Therefore, a) I've added an associated data flag to indicate the last chunk and b) check the nonce is the same for the entire stream
// However, a key still can't be reused much due to the short random nonce (64 bits)
// https://github.com/minio/sio/blob/master/DARE.md
public sealed class DAREv1 : IDisposable
{
    public const int HeaderSize = 16;
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int TagSize = ChaCha20Poly1305.TagSize;
    public const int MinPlaintextChunkSize = 1;
    public const int MaxPlaintextChunkSize = 65536; // 64 KiB
    private const uint MaxCounter = uint.MaxValue; // 2^(32)-1
    private const byte Version = 0x10;
    private const byte CipherSuite = 0x01; // CHACHA20_POLY1305
    private readonly byte[] _key = GC.AllocateArray<byte>(KeySize, pinned: true);
    private readonly byte[] _header = GC.AllocateArray<byte>(HeaderSize, pinned: true);
    private uint _sequenceNumber;
    private uint _finalChunkOffset;
    private bool _encryption;
    private bool _firstChunk;
    private bool _finalChunkSeeked;
    private bool _seeking;
    private bool _finalized;
    private bool _disposed;

    public DAREv1(ReadOnlySpan<byte> key, bool encryption)
    {
        Reinitialize(key, encryption);
    }

    public void Reinitialize(ReadOnlySpan<byte> key, bool encryption)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(DAREv1)); }
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        _header[0] = Version;
        _header[1] = CipherSuite;
        if (encryption) {
            SecureRandom.Fill(_header.AsSpan()[8..]);
        }
        key.CopyTo(_key);
        _sequenceNumber = 0;
        _encryption = encryption;
        _finalized = false;
        _seeking = false;
        _firstChunk = true;
        _finalChunkSeeked = false;
        _finalChunkOffset = 0;
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, bool finalChunk = false)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(DAREv1)); }
        if (!_encryption) { throw new InvalidOperationException("Cannot encrypt chunks on a stream set for decryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been encrypted."); }
        if (_sequenceNumber == MaxCounter && !finalChunk) { throw new ArgumentException("This chunk must be the final chunk as the maximum counter has been reached."); }
        Validation.SizeBetween(nameof(plaintextChunk), plaintextChunk.Length, MinPlaintextChunkSize, MaxPlaintextChunkSize);
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + HeaderSize + TagSize);

        Span<byte> header = _header.AsSpan(), chunkInfo = header[..4], payloadSize = header[2..4], sequenceNumber = header[4..8];
        BinaryPrimitives.WriteUInt16LittleEndian(payloadSize, (ushort)(plaintextChunk.Length - 1));
        BinaryPrimitives.WriteUInt32LittleEndian(sequenceNumber, _sequenceNumber);
        // This final chunk flag is missing from the specification
        Span<byte> associatedData = !finalChunk ? chunkInfo : stackalloc byte[chunkInfo.Length + 1];
        if (finalChunk) {
            _finalized = true;
            chunkInfo.CopyTo(associatedData);
            associatedData[^1] = 0x01;
        }
        header.CopyTo(ciphertextChunk[..HeaderSize]);
        ChaCha20Poly1305.Encrypt(ciphertextChunk[HeaderSize..], plaintextChunk, nonce: header[4..], _key, associatedData);
        _sequenceNumber++;
    }

    public void DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, bool finalChunk = false)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(DAREv1)); }
        if (_encryption) { throw new InvalidOperationException("Cannot decrypt chunks on a stream set for encryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been decrypted."); }
        if (_sequenceNumber == MaxCounter && !finalChunk) { throw new ArgumentException("This chunk must be the final chunk as the maximum counter has been reached."); }
        Validation.SizeBetween(nameof(ciphertextChunk), ciphertextChunk.Length, MinPlaintextChunkSize + HeaderSize + TagSize, MaxPlaintextChunkSize + HeaderSize + TagSize);
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - HeaderSize - TagSize);

        ReadOnlySpan<byte> header = ciphertextChunk[..HeaderSize], chunkInfo = header[..4], sequenceNumber = header[4..8], nonce = header[8..];
        // Check the nonce is the same for the entire stream
        Span<byte> streamNonce = _header.AsSpan()[8..], expectedSequenceNumber = _header.AsSpan()[4..8];
        if (_firstChunk) {
            nonce.CopyTo(streamNonce);
            _firstChunk = false;
        }
        if (header[0] != _header[0]) { throw new NotSupportedException("Unsupported version."); }
        if (header[1] != _header[1]) { throw new NotSupportedException("Unsupported cipher."); }
        uint payloadSize = (uint)BinaryPrimitives.ReadUInt16LittleEndian(header[2..4]) + 1;
        if (plaintextChunk.Length != payloadSize) { throw new ArgumentException("Incorrect chunk size."); }
        BinaryPrimitives.WriteUInt32LittleEndian(expectedSequenceNumber, _sequenceNumber);
        if (!ConstantTime.Equals(sequenceNumber, expectedSequenceNumber)) { throw new CryptographicException("Chunk out of order."); }
        // This check is missing from the specification
        if (!ConstantTime.Equals(nonce, streamNonce)) { throw new CryptographicException("Chunk swapped between streams."); }

        Span<byte> associatedData = !finalChunk ? Span<byte>.Empty : stackalloc byte[chunkInfo.Length + 1];
        if (finalChunk) {
            if (!_seeking) { _finalized = true; }
            chunkInfo.CopyTo(associatedData);
            associatedData[^1] = 0x01;
        }
        ChaCha20Poly1305.Decrypt(plaintextChunk, ciphertextChunk[HeaderSize..], nonce: header[4..], _key, !finalChunk ? chunkInfo : associatedData);
        _sequenceNumber++;
    }

    public void SeekChunk(uint sequenceNumber, bool finalChunk = false)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(DAREv1)); }
        if (_encryption) { throw new InvalidOperationException("Cannot seek chunks on a stream set for encryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been decrypted without seeking."); }
        if (!_seeking && !finalChunk) { throw new CryptographicException("The final chunk must be decrypted before further seeking to detect stream truncation."); }
        if (!finalChunk && _finalChunkSeeked && sequenceNumber >= _finalChunkOffset) { throw new ArgumentOutOfRangeException(nameof(sequenceNumber), sequenceNumber, $"{nameof(sequenceNumber)} cannot be greater than {_finalChunkOffset} (the final chunk) and {nameof(finalChunk)} must be true if {nameof(sequenceNumber)} equals {_finalChunkOffset}."); }
        if (finalChunk && _finalChunkSeeked && sequenceNumber != _finalChunkOffset) { throw new ArgumentOutOfRangeException(nameof(sequenceNumber), sequenceNumber, $"{nameof(sequenceNumber)} must be {_finalChunkOffset} for the final chunk."); }

        // Not setting _finalized to allow the final chunk to be decrypted twice (rather than caching it)
        _seeking = true;
        _sequenceNumber = sequenceNumber;
        if (finalChunk) {
            _finalChunkSeeked = true;
            _finalChunkOffset = sequenceNumber;
        }
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        SecureMemory.ZeroMemory(_key);
        SecureMemory.ZeroMemory(_header);
        _sequenceNumber = 0;
        _finalChunkOffset = 0;
        _disposed = true;
    }
}
