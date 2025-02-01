using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;

namespace Chnkd;

public sealed class STREAM : IDisposable
{
    public const int HeaderSize = XChaCha20Poly1305.NonceSize;
    public const int KeySize = AEGIS256.KeySize;
    public const int TagSize = AEGIS256.TagSize;
    private const ulong MaxCounter = 72057594037927935; // 2^(56)-1
    private readonly byte[] _key = GC.AllocateArray<byte>(AEGIS256.KeySize, pinned: true);
    private readonly byte[] _nonce = GC.AllocateArray<byte>(AEGIS256.NonceSize, pinned: true);
    private ulong _counter;
    private ulong _finalChunkOffset;
    private bool _encryption;
    private bool _seeking;
    private bool _finalized;
    private bool _disposed;

    public STREAM(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        Reinitialize(header, key, encryption);
    }

    public void Reinitialize(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(STREAM)); }
        Validation.EqualToSize(nameof(header), header.Length, HeaderSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        if (encryption) {
            SecureRandom.Fill(header);
        }
        header.CopyTo(_nonce);
        key.CopyTo(_key);
        _counter = 1;
        _encryption = encryption;
        _finalized = false;
        _seeking = false;
        _finalChunkOffset = 0;
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, bool finalChunk = false)
    {
        EncryptChunk(ciphertextChunk, plaintextChunk, associatedData: ReadOnlySpan<byte>.Empty, finalChunk);
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, bool finalChunk = false)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(STREAM)); }
        if (!_encryption) { throw new InvalidOperationException("Cannot encrypt chunks on a stream set for decryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been encrypted."); }
        if (_counter == MaxCounter && !finalChunk) { throw new ArgumentException("This chunk must be the final chunk as the maximum counter has been reached."); }
        if (_counter > MaxCounter) { throw new OverflowException("The maximum number of chunks has been reached."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);

        if (finalChunk) { _finalized = true; }
        Span<byte> nonce = _nonce.AsSpan(), counter = nonce[^8..];
        BinaryPrimitives.WriteUInt64LittleEndian(counter, _counter);
        nonce[^1] = Convert.ToByte(finalChunk);
        AEGIS256.Encrypt(ciphertextChunk, plaintextChunk, nonce, _key, associatedData);
        _counter++;
    }

    public void DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, bool finalChunk = false)
    {
        DecryptChunk(plaintextChunk, ciphertextChunk, associatedData: ReadOnlySpan<byte>.Empty, finalChunk);
    }

    public void DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData, bool finalChunk = false)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(STREAM)); }
        if (_encryption) { throw new InvalidOperationException("Cannot decrypt chunks on a stream set for encryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been decrypted."); }
        if (_counter == MaxCounter && !finalChunk) { throw new ArgumentException("This chunk must be the final chunk as the maximum counter has been reached."); }
        if (_counter > MaxCounter) { throw new OverflowException("The maximum number of chunks has been reached."); }
        Validation.NotLessThanMin(nameof(ciphertextChunk), ciphertextChunk.Length, TagSize);
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - TagSize);

        if (finalChunk && !_seeking) { _finalized = true; }
        Span<byte> nonce = _nonce.AsSpan(), counter = nonce[^8..];
        BinaryPrimitives.WriteUInt64LittleEndian(counter, _counter);
        nonce[^1] = Convert.ToByte(finalChunk);
        AEGIS256.Decrypt(plaintextChunk, ciphertextChunk, nonce, _key, associatedData);
        _counter++;
    }

    public void SeekChunk(ulong chunkOffset, bool finalChunk = false)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(STREAM)); }
        if (_encryption) { throw new InvalidOperationException("Cannot seek chunks on a stream set for encryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been decrypted without seeking."); }
        if (!_seeking && !finalChunk) { throw new CryptographicException("The final chunk must be decrypted before further seeking to detect stream truncation."); }
        if (chunkOffset is 0 or > MaxCounter) { throw new ArgumentOutOfRangeException(nameof(chunkOffset), chunkOffset, $"{nameof(chunkOffset)} must be between 1 and {MaxCounter}."); }
        if (!finalChunk && _finalChunkOffset != 0 && chunkOffset >= _finalChunkOffset) { throw new ArgumentOutOfRangeException(nameof(chunkOffset), chunkOffset, $"{nameof(chunkOffset)} cannot be greater than {_finalChunkOffset} (the final chunk) and {nameof(finalChunk)} must be true if {nameof(chunkOffset)} equals {_finalChunkOffset}."); }
        if (finalChunk && _finalChunkOffset != 0 && chunkOffset != _finalChunkOffset) { throw new ArgumentOutOfRangeException(nameof(chunkOffset), chunkOffset, $"{nameof(chunkOffset)} must be {_finalChunkOffset} for the final chunk."); }

        // Not setting _finalized to allow the final chunk to be decrypted twice (rather than caching it)
        _seeking = true;
        _counter = chunkOffset;
        if (finalChunk) { _finalChunkOffset = chunkOffset; }
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        SecureMemory.ZeroMemory(_key);
        SecureMemory.ZeroMemory(_nonce);
        _counter = 0;
        _finalChunkOffset = 0;
        _disposed = true;
    }
}
