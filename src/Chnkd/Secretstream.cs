using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace Chnkd;

// https://doc.libsodium.org/secret-key_cryptography/secretstream#algorithm
public sealed class Secretstream : IDisposable
{
    public const int HeaderSize = XChaCha20Poly1305.NonceSize;
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int TagSize = ChaCha20Poly1305.TagSize + 1;
    private const int CounterSize = ChaCha20Poly1305.NonceSize - SubnonceSize;
    private const int SubnonceSize = XChaCha20Poly1305.NonceSize - HChaCha20.NonceSize;
    private readonly byte[] _key = GC.AllocateArray<byte>(ChaCha20Poly1305.KeySize, pinned: true);
    private readonly byte[] _nonce = GC.AllocateArray<byte>(ChaCha20Poly1305.NonceSize, pinned: true);
    private uint _counter;
    private bool _encryption;
    private bool _finalized;
    private bool _disposed;

    // Libsodium calls this the 'tag'. I prefer 'flag' to avoid confusion with the Poly1305 tag
    // crypto_secretstream_xchacha20poly1305_TAG_PUSH has been renamed to Boundary
    public enum ChunkFlag
    {
        Message = 0x00,
        Boundary = 0x01,
        Rekey = 0x02,
        Final = 0x03
    }

    public Secretstream(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        Reinitialize(header, key, encryption);
    }

    public void Reinitialize(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(Secretstream)); }
        Validation.EqualToSize(nameof(header), header.Length, HeaderSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        if (encryption) {
            SecureRandom.Fill(header);
        }
        Span<byte> subkey = stackalloc byte[HChaCha20.OutputSize], subnonce = _nonce.AsSpan()[^SubnonceSize..];
        HChaCha20.DeriveKey(subkey, key, header[..HChaCha20.NonceSize]);
        header[HChaCha20.NonceSize..].CopyTo(subnonce);
        subkey.CopyTo(_key);
        SecureMemory.ZeroMemory(subkey);
        _counter = 1;
        _encryption = encryption;
        _finalized = false;
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ChunkFlag chunkFlag = ChunkFlag.Message)
    {
        EncryptChunk(ciphertextChunk, plaintextChunk, associatedData: ReadOnlySpan<byte>.Empty, chunkFlag);
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, ChunkFlag chunkFlag = ChunkFlag.Message)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(Secretstream)); }
        if (!_encryption) { throw new InvalidOperationException("Cannot encrypt chunks on a stream set for decryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been encrypted."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);

        if (chunkFlag == ChunkFlag.Final) { _finalized = true; }
        Span<byte> nonce = _nonce.AsSpan(), counter = nonce[..CounterSize], subnonce = nonce[CounterSize..];
        BinaryPrimitives.WriteUInt32LittleEndian(counter, _counter);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize], macKey = block0[..Poly1305.KeySize];
        ChaCha20.Fill(block0, _nonce, _key);

        // Zero pad the chunk flag before encrypting
        Span<byte> flagBlock = stackalloc byte[ChaCha20.BlockSize]; flagBlock.Clear();
        flagBlock[0] = (byte)chunkFlag;
        ChaCha20.Encrypt(flagBlock, flagBlock, _nonce, _key, counter: 1);
        // Truncate for the ciphertext output but internally authenticate the entire block
        ciphertextChunk[0] = flagBlock[0];

        Span<byte> ciphertext = ciphertextChunk[1..^Poly1305.TagSize], tag = ciphertextChunk[^Poly1305.TagSize..];
        ChaCha20.Encrypt(ciphertext, plaintextChunk, _nonce, _key, counter: 2);
        ComputeTag(tag, associatedData, flagBlock, ciphertext, macKey);
        SecureMemory.ZeroMemory(block0);
        SecureMemory.ZeroMemory(flagBlock);

        for (int i = 0; i < subnonce.Length; i++) {
            subnonce[i] ^= tag[i];
        }

        _counter++;
        if (_counter == 0 || chunkFlag == ChunkFlag.Rekey) {
            Rekey();
        }
    }

    public ChunkFlag DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk)
    {
        return DecryptChunk(plaintextChunk, ciphertextChunk, associatedData: ReadOnlySpan<byte>.Empty);
    }

    public ChunkFlag DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(Secretstream)); }
        if (_encryption) { throw new InvalidOperationException("Cannot decrypt chunks on a stream set for encryption."); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been decrypted."); }
        Validation.NotLessThanMin(nameof(ciphertextChunk), ciphertextChunk.Length, TagSize);
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - TagSize);

        Span<byte> nonce = _nonce.AsSpan(), counter = nonce[..CounterSize], subnonce = nonce[CounterSize..];
        BinaryPrimitives.WriteUInt32LittleEndian(counter, _counter);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize], macKey = block0[..Poly1305.KeySize];
        ChaCha20.Fill(block0, _nonce, _key);

        Span<byte> flagBlock = stackalloc byte[ChaCha20.BlockSize]; flagBlock.Clear();
        // Encrypt() will actually decrypt the first byte due to the keystream XOR
        flagBlock[0] = ciphertextChunk[0];
        ChaCha20.Encrypt(flagBlock, flagBlock, _nonce, _key, counter: 1);
        var chunkFlag = (ChunkFlag)flagBlock[0];
        if (chunkFlag == ChunkFlag.Final) { _finalized = true; }
        // Set this back to the ciphertext value for authentication (ChaCha20-Poly1305 is Encrypt-then-MAC)
        flagBlock[0] = ciphertextChunk[0];

        ReadOnlySpan<byte> ciphertext = ciphertextChunk[1..^Poly1305.TagSize], tag = ciphertextChunk[^Poly1305.TagSize..];
        Span<byte> computedTag = stackalloc byte[Poly1305.TagSize];
        ComputeTag(computedTag, associatedData, flagBlock, ciphertext, macKey);
        SecureMemory.ZeroMemory(block0);
        SecureMemory.ZeroMemory(flagBlock);

        bool valid = ConstantTime.Equals(tag, computedTag);
        SecureMemory.ZeroMemory(computedTag);
        if (!valid) {
            throw new CryptographicException();
        }
        ChaCha20.Decrypt(plaintextChunk, ciphertext, _nonce, _key, counter: 2);

        for (int i = 0; i < subnonce.Length; i++) {
            subnonce[i] ^= tag[i];
        }

        _counter++;
        if (_counter == 0 || chunkFlag == ChunkFlag.Rekey) {
            Rekey();
        }
        return chunkFlag;
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> flagBlock, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding = stackalloc byte[16]; padding.Clear();
        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        if (associatedData.Length % 16 != 0) {
            poly1305.Update(padding[(associatedData.Length % 16)..]);
        }
        poly1305.Update(flagBlock);
        poly1305.Update(ciphertext);
        // Note that this is different to libsodium's secretstream due to an alignment error in the libsodium code
        // https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c#L151
        if ((flagBlock.Length + ciphertext.Length) % 16 != 0) {
            poly1305.Update(padding[((flagBlock.Length + ciphertext.Length) % 16)..]);
        }
        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)(flagBlock.Length + ciphertext.Length));
        poly1305.Update(padding);
        poly1305.Finalize(tag);
    }

    public void Rekey()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(Secretstream)); }
        if (_finalized) { throw new InvalidOperationException("The final chunk has already been processed."); }

        Span<byte> keyAndNonce = stackalloc byte[KeySize + SubnonceSize];
        Span<byte> nonce = _nonce.AsSpan(), counter = nonce[..CounterSize], subnonce = nonce[CounterSize..];
        _key.CopyTo(keyAndNonce);
        subnonce.CopyTo(keyAndNonce[KeySize..]);

        BinaryPrimitives.WriteUInt32LittleEndian(counter, _counter);
        ChaCha20.Encrypt(keyAndNonce, keyAndNonce, _nonce, _key);

        keyAndNonce[..KeySize].CopyTo(_key);
        keyAndNonce[KeySize..].CopyTo(subnonce);
        _counter = 1;
        SecureMemory.ZeroMemory(keyAndNonce);
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        SecureMemory.ZeroMemory(_key);
        SecureMemory.ZeroMemory(_nonce);
        _counter = 0;
        _disposed = true;
    }
}
