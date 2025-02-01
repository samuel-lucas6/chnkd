using System.Security.Cryptography;

namespace Chnkd.Tests;

[TestClass]
public class STREAMTests
{
    public static IEnumerable<object[]> EncryptParameters()
    {
        yield return
        [
            "1001000000000000000000000000000000000000000000000000000000000000",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        ];
        yield return
        [
            "1001000000000000000000000000000000000000000000000000000000000000",
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a",
            ""
        ];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(24, STREAM.HeaderSize);
        Assert.AreEqual(32, STREAM.KeySize);
        Assert.AreEqual(32, STREAM.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void EncryptChunk_DecryptChunk_SingleChunk_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[STREAM.HeaderSize]; h.Clear();
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> ad = Convert.FromHexString(associatedData);
        Span<byte> c = stackalloc byte[p.Length + STREAM.TagSize];

        using var stream = new STREAM(h, k, encryption: true);
        Assert.IsFalse(h.SequenceEqual(new byte[h.Length]));

        stream.EncryptChunk(c, p, ad, finalChunk: true);
        p.Clear();

        stream.Reinitialize(h, k, encryption: false);
        stream.DecryptChunk(p, c, ad, finalChunk: true);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void EncryptChunk_DecryptChunk_MultipleChunks_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[STREAM.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];

        Span<byte> c = stackalloc byte[p.Length + STREAM.TagSize * 4];
        Span<byte> c1 = c[..(p1.Length + STREAM.TagSize)], c2 = c.Slice(c1.Length, p2.Length + STREAM.TagSize);
        Span<byte> c3 = c.Slice(c1.Length + c2.Length, p3.Length + STREAM.TagSize), c4 = c[^(p4.Length + STREAM.TagSize)..];

        using var stream = new STREAM(h, k, encryption: true);
        stream.EncryptChunk(c1, p1, ad);
        stream.EncryptChunk(c2, p2);
        stream.EncryptChunk(c3, p3);
        stream.EncryptChunk(c4, p4, finalChunk: true);
        p.Clear();

        stream.Reinitialize(h, k, encryption: false);
        stream.DecryptChunk(p1, c1, ad);
        stream.DecryptChunk(p2, c2);
        stream.DecryptChunk(p3, c3);
        stream.DecryptChunk(p4, c4, finalChunk: true);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void SeekChunk_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[STREAM.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];

        Span<byte> c = stackalloc byte[p.Length + STREAM.TagSize * 4];
        Span<byte> c1 = c[..(p1.Length + STREAM.TagSize)], c2 = c.Slice(c1.Length, p2.Length + STREAM.TagSize);
        Span<byte> c3 = c.Slice(c1.Length + c2.Length, p3.Length + STREAM.TagSize), c4 = c[^(p4.Length + STREAM.TagSize)..];

        using var stream = new STREAM(h, k, encryption: true);
        stream.EncryptChunk(c1, p1, ad);
        stream.EncryptChunk(c2, p2);
        stream.EncryptChunk(c3, p3);
        stream.EncryptChunk(c4, p4, finalChunk: true);
        p.Clear();

        stream.Reinitialize(h, k, encryption: false);
        // Check the stream hasn't been truncated before further seeking
        stream.SeekChunk(4, finalChunk: true);
        stream.DecryptChunk(p4, c4, finalChunk: true);
        // Check the associated data for the entire stream
        stream.SeekChunk(1);
        stream.DecryptChunk(p1, c1, ad);
        stream.SeekChunk(3);
        stream.DecryptChunk(p3, c3);
        stream.SeekChunk(2);
        stream.DecryptChunk(p2, c2);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void DecryptChunk_SingleChunk_Tampered(string key, string plaintext, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "h", new byte[STREAM.HeaderSize] },
            { "k", Convert.FromHexString(key) },
            { "c", new byte[p.Length + STREAM.TagSize] },
            { "ad", Convert.FromHexString(associatedData) }
        };

        using var stream = new STREAM(parameters["h"], parameters["k"], encryption: true);
        stream.EncryptChunk(parameters["c"], p, parameters["ad"], finalChunk: true);

        // Wrong parameters/stream modification
        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            stream.Reinitialize(parameters["h"], parameters["k"], encryption: false);
            Assert.ThrowsException<CryptographicException>(() => stream.DecryptChunk(p, parameters["c"], parameters["ad"], finalChunk: true));
            param[0]--;
        }
        // Stream extension
        stream.Reinitialize(parameters["h"], parameters["k"], encryption: false);
        Assert.ThrowsException<CryptographicException>(() => stream.DecryptChunk(p, parameters["c"], parameters["ad"], finalChunk: false));
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void DecryptChunk_MultiChunk_Tampered(string key, string plaintext, string associatedData)
    {
        var h = new byte[STREAM.HeaderSize];
        var k = Convert.FromHexString(key);
        var ad = Convert.FromHexString(associatedData);

        var p = Convert.FromHexString(plaintext);
        byte[] p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];

        var c = new byte[p.Length + STREAM.TagSize * 4];
        byte[] c1 = c[..42], c2 = c[42..84], c3 = c[84..126], c4 = c[126..];

        using var stream = new STREAM(h, k, encryption: true);
        stream.EncryptChunk(c1, p1, ad);
        stream.EncryptChunk(c2, p2);
        stream.EncryptChunk(c3, p3);
        stream.EncryptChunk(c4, p4, finalChunk: true);
        Array.Clear(p);

        stream.Reinitialize(h, k, encryption: false);
        stream.DecryptChunk(p1, c1, ad);
        // Chunk reordering/deletion
        Assert.ThrowsException<CryptographicException>(() => stream.DecryptChunk(p3, c3));
        stream.DecryptChunk(p2, c2);
        // Chunk duplication
        Assert.ThrowsException<CryptographicException>(() => stream.DecryptChunk(p2, c2));
        // Stream truncation
        Assert.ThrowsException<CryptographicException>(() => stream.DecryptChunk(p3, c3, finalChunk: true));
    }

    [TestMethod]
    [DataRow(STREAM.HeaderSize + 1, STREAM.KeySize, STREAM.TagSize, 0)]
    [DataRow(STREAM.HeaderSize - 1, STREAM.KeySize, STREAM.TagSize, 0)]
    [DataRow(STREAM.HeaderSize, STREAM.KeySize + 1, STREAM.TagSize, 0)]
    [DataRow(STREAM.HeaderSize, STREAM.KeySize - 1, STREAM.TagSize, 0)]
    [DataRow(STREAM.HeaderSize, STREAM.KeySize, STREAM.TagSize + 1, 0)]
    [DataRow(STREAM.HeaderSize, STREAM.KeySize, STREAM.TagSize - 1, 0)]
    public void EncryptChunk_DecryptChunk_Invalid(int headerSize, int keySize, int ciphertextSize, int plaintextSize)
    {
        var h = new byte[headerSize];
        var k = new byte[keySize];
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];

        if (headerSize != STREAM.HeaderSize || keySize != STREAM.KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new STREAM(h, k, encryption: true));
        }
        else {
            using var encryption = new STREAM(h, k, encryption: true);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => encryption.EncryptChunk(c, p));

            using var decryption = new STREAM(h, k, encryption: false);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => decryption.DecryptChunk(p, c));
        }
    }

    [TestMethod]
    public void SeekChunk_Invalid()
    {
        const ulong finalChunkOffset = 4;
        var h = new byte[STREAM.HeaderSize];
        var k = new byte[STREAM.KeySize];

        using var stream = new STREAM(h, k, encryption: false);

        // Need to decrypt final chunk first to detect stream truncation
        Assert.ThrowsException<CryptographicException>(() => stream.SeekChunk(finalChunkOffset, finalChunk: false));
        stream.SeekChunk(finalChunkOffset, finalChunk: true);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => stream.SeekChunk(0));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => stream.SeekChunk(ulong.MaxValue));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => stream.SeekChunk(finalChunkOffset + 1));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => stream.SeekChunk(finalChunkOffset, finalChunk: false));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => stream.SeekChunk(finalChunkOffset - 1, finalChunk: true));
    }

    [TestMethod]
    public void Stream_InvalidOperation()
    {
        var h = new byte[STREAM.HeaderSize];
        var k = new byte[STREAM.KeySize];
        var p = new byte[h.Length];
        var c = new byte[p.Length + STREAM.TagSize];

        using var encryption = new STREAM(h, k, encryption: true);
        Assert.ThrowsException<InvalidOperationException>(() => encryption.DecryptChunk(p, c));
        Assert.ThrowsException<InvalidOperationException>(() => encryption.SeekChunk(1));
        encryption.EncryptChunk(c, p, finalChunk: true);
        Assert.ThrowsException<InvalidOperationException>(() => encryption.EncryptChunk(c, p));

        using var decryption = new STREAM(h, k, encryption: false);
        Assert.ThrowsException<InvalidOperationException>(() => decryption.EncryptChunk(c, p));
        decryption.DecryptChunk(p, c, finalChunk: true);
        Assert.ThrowsException<InvalidOperationException>(() => decryption.DecryptChunk(p, c));
        Assert.ThrowsException<InvalidOperationException>(() => decryption.SeekChunk(1));
    }

    [TestMethod]
    public void Stream_Disposed()
    {
        var h = new byte[STREAM.HeaderSize];
        var k = new byte[STREAM.KeySize];
        var p = new byte[h.Length];
        var c = new byte[p.Length + STREAM.TagSize];

        var stream = new STREAM(h, k, encryption: true);
        stream.Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() => stream.Reinitialize(h, k, encryption: false));
        Assert.ThrowsException<ObjectDisposedException>(() => stream.EncryptChunk(c, p));
        Assert.ThrowsException<ObjectDisposedException>(() => stream.DecryptChunk(p, c));
        Assert.ThrowsException<ObjectDisposedException>(() => stream.SeekChunk(1));
    }
}
