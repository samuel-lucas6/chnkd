using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;

namespace Chnkd;

public sealed class Monostream : IDisposable
{
    public const int HeaderSize = XChaCha20Poly1305.NonceSize;
    public const int KeySize = ChaCha20.KeySize;
    public const int TagSize = Poly1305.TagSize;
    private readonly byte[] _key = GC.AllocateArray<byte>(ChaCha20.KeySize, pinned: true);
    private readonly byte[] _nonce = GC.AllocateArray<byte>(ChaCha20.NonceSize, pinned: true);
    private bool _encryption;
    private bool _finalized;
    private bool _disposed;

    public Monostream(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        Reinitialize(header, key, encryption);
    }

    public void Reinitialize(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(Monostream)); }
        Validation.EqualToSize(nameof(header), header.Length, HeaderSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        if (encryption) {
            SecureRandom.Fill(header);
        }
        // Do nonce extension once per stream
        Span<byte> subkey = stackalloc byte[HChaCha20.OutputSize];
        HChaCha20.DeriveKey(subkey, key, header[..HChaCha20.NonceSize]);
        header[HChaCha20.NonceSize..].CopyTo(_nonce.AsSpan()[^(HeaderSize - HChaCha20.NonceSize)..]);
        subkey.CopyTo(_key);
        SecureMemory.ZeroMemory(subkey);
        _encryption = encryption;
        _finalized = false;
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, bool finalChunk = false)
    {
        EncryptChunk(ciphertextChunk, plaintextChunk, associatedData: ReadOnlySpan<byte>.Empty, finalChunk);
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, bool finalChunk = false)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(Monostream)); }
        if (!_encryption) { throw new InvalidOperationException("Cannot encrypt chunks on a stream set for decryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been encrypted."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize], macKey = block0[..Poly1305.KeySize], nextEncKey = block0[Poly1305.KeySize..];
        ChaCha20.Fill(block0, _nonce, _key);
        Span<byte> ciphertext = ciphertextChunk[..^TagSize], tag = ciphertextChunk[^TagSize..];
        ChaCha20.Encrypt(ciphertext, plaintextChunk, _nonce, _key, counter: 1);
        if (finalChunk) {
            _finalized = true;
            Span<byte> ad = GC.AllocateArray<byte>(associatedData.Length + 1, pinned: true);
            associatedData.CopyTo(ad);
            ad[^1] = 0x01;
            ComputeTag(tag, ad, ciphertext, macKey);
            SecureMemory.ZeroMemory(ad);
        }
        else {
            ComputeTag(tag, associatedData, ciphertext, macKey);
        }
        nextEncKey.CopyTo(_key);
        SecureMemory.ZeroMemory(block0);
    }

    public void DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, bool finalChunk = false)
    {
        DecryptChunk(plaintextChunk, ciphertextChunk, associatedData: ReadOnlySpan<byte>.Empty, finalChunk);
    }

    public void DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData, bool finalChunk = false)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(Monostream)); }
        if (_encryption) { throw new InvalidOperationException("Cannot decrypt chunks on a stream set for encryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been decrypted."); }
        Validation.NotLessThanMin(nameof(ciphertextChunk), ciphertextChunk.Length, TagSize);
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - TagSize);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize], macKey = block0[..Poly1305.KeySize], nextEncKey = block0[Poly1305.KeySize..];
        ChaCha20.Fill(block0, _nonce, _key);

        ReadOnlySpan<byte> ciphertext = ciphertextChunk[..^TagSize], tag = ciphertextChunk[^TagSize..];
        Span<byte> computedTag = stackalloc byte[TagSize];
        if (finalChunk) {
            _finalized = true;
            Span<byte> ad = GC.AllocateArray<byte>(associatedData.Length + 1, pinned: true);
            associatedData.CopyTo(ad);
            ad[^1] = 0x01;
            ComputeTag(computedTag, ad, ciphertext, macKey);
            SecureMemory.ZeroMemory(ad);
        }
        else {
            ComputeTag(computedTag, associatedData, ciphertext, macKey);
        }

        if (!ConstantTime.Equals(tag, computedTag)) {
            SecureMemory.ZeroMemory(block0);
            SecureMemory.ZeroMemory(computedTag);
            throw new CryptographicException();
        }

        ChaCha20.Decrypt(plaintextChunk, ciphertext, _nonce, _key, counter: 1);
        nextEncKey.CopyTo(_key);
        SecureMemory.ZeroMemory(block0);
        SecureMemory.ZeroMemory(computedTag);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding = stackalloc byte[16]; padding.Clear();
        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        if (associatedData.Length % 16 != 0) {
            poly1305.Update(padding[(associatedData.Length % 16)..]);
        }
        poly1305.Update(ciphertext);
        if (ciphertext.Length % 16 != 0) {
            poly1305.Update(padding[(ciphertext.Length % 16)..]);
        }
        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)ciphertext.Length);
        poly1305.Update(padding);
        poly1305.Finalize(tag);
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        SecureMemory.ZeroMemory(_key);
        SecureMemory.ZeroMemory(_nonce);
        _disposed = true;
    }
}
