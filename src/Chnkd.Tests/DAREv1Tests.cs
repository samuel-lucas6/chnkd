using System.Security.Cryptography;

namespace Chnkd.Tests;

[TestClass]
public class DAREv1Tests
{
    public static IEnumerable<object[]> EncryptParameters()
    {
        yield return
        [
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
        ];
        yield return
        [
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d"
        ];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, DAREv1.HeaderSize);
        Assert.AreEqual(32, DAREv1.KeySize);
        Assert.AreEqual(16, DAREv1.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void EncryptChunk_DecryptChunk_SingleChunk_Valid(string key, string plaintext)
    {
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + DAREv1.HeaderSize + DAREv1.TagSize];

        using var dare = new DAREv1(k, encryption: true);
        dare.EncryptChunk(c, p, finalChunk: true);
        p.Clear();

        dare.Reinitialize(k, encryption: false);
        dare.DecryptChunk(p, c, finalChunk: true);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void EncryptChunk_DecryptChunk_MultipleChunks_Valid(string key, string plaintext)
    {
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];

        Span<byte> c = stackalloc byte[p.Length + (DAREv1.HeaderSize + DAREv1.TagSize) * 4];
        Span<byte> c1 = c[..(p1.Length + DAREv1.HeaderSize + DAREv1.TagSize)], c2 = c.Slice(c1.Length, p2.Length + DAREv1.HeaderSize + DAREv1.TagSize);
        Span<byte> c3 = c.Slice(c1.Length + c2.Length, p3.Length + DAREv1.HeaderSize + DAREv1.TagSize), c4 = c[^(p4.Length + DAREv1.HeaderSize + DAREv1.TagSize)..];

        using var dare = new DAREv1(k, encryption: true);
        dare.EncryptChunk(c1, p1);
        dare.EncryptChunk(c2, p2);
        dare.EncryptChunk(c3, p3);
        dare.EncryptChunk(c4, p4, finalChunk: true);
        p.Clear();

        dare.Reinitialize(k, encryption: false);
        dare.DecryptChunk(p1, c1);
        dare.DecryptChunk(p2, c2);
        dare.DecryptChunk(p3, c3);
        dare.DecryptChunk(p4, c4, finalChunk: true);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void SeekChunk_Valid(string key, string plaintext)
    {
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];

        Span<byte> c = stackalloc byte[p.Length + (DAREv1.HeaderSize + DAREv1.TagSize) * 4];
        Span<byte> c1 = c[..(p1.Length + DAREv1.HeaderSize + DAREv1.TagSize)], c2 = c.Slice(c1.Length, p2.Length + DAREv1.HeaderSize + DAREv1.TagSize);
        Span<byte> c3 = c.Slice(c1.Length + c2.Length, p3.Length + DAREv1.HeaderSize + DAREv1.TagSize), c4 = c[^(p4.Length + DAREv1.HeaderSize + DAREv1.TagSize)..];

        using var dare = new DAREv1(k, encryption: true);
        dare.EncryptChunk(c1, p1);
        dare.EncryptChunk(c2, p2);
        dare.EncryptChunk(c3, p3);
        dare.EncryptChunk(c4, p4, finalChunk: true);
        p.Clear();

        dare.Reinitialize(k, encryption: false);
        // Check the stream hasn't been truncated before further seeking
        dare.SeekChunk(3, finalChunk: true);
        dare.DecryptChunk(p4, c4, finalChunk: true);
        dare.SeekChunk(0);
        dare.DecryptChunk(p1, c1);
        dare.SeekChunk(2);
        dare.DecryptChunk(p3, c3);
        dare.SeekChunk(1);
        dare.DecryptChunk(p2, c2);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void DecryptChunk_SingleChunk_Tampered(string key, string plaintext)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "k", Convert.FromHexString(key) },
            { "c", new byte[p.Length + DAREv1.HeaderSize + DAREv1.TagSize] }
        };

        using var dare = new DAREv1(parameters["k"], encryption: true);
        dare.EncryptChunk(parameters["c"], p, finalChunk: true);

        // Header tampering
        dare.Reinitialize(parameters["k"], encryption: false);
        for (int i = 0; i < DAREv1.HeaderSize; i++) {
            parameters["c"][i]++;
            if (i is 0 or 1) {
                Assert.ThrowsException<NotSupportedException>(() => dare.DecryptChunk(p, parameters["c"], finalChunk: true));
            }
            else if (i is 2 or 3) {
                Assert.ThrowsException<ArgumentException>(() => dare.DecryptChunk(p, parameters["c"], finalChunk: true));
            }
            else {
                Assert.ThrowsException<CryptographicException>(() => dare.DecryptChunk(p, parameters["c"], finalChunk: true));
            }
            parameters["c"][i]--;
        }
        // Wrong parameters/stream modification
        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[^1]++;
            dare.Reinitialize(parameters["k"], encryption: false);
            Assert.ThrowsException<CryptographicException>(() => dare.DecryptChunk(p, parameters["c"], finalChunk: true));
            param[^1]--;
        }
        // Stream extension
        dare.Reinitialize(parameters["k"], encryption: false);
        Assert.ThrowsException<CryptographicException>(() => dare.DecryptChunk(p, parameters["c"], finalChunk: false));
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void DecryptChunk_MultiChunk_Tampered(string key, string plaintext)
    {
        var k = Convert.FromHexString(key);
        var p = Convert.FromHexString(plaintext);
        byte[] p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];

        var c = new byte[p.Length + (DAREv1.HeaderSize + DAREv1.TagSize) * 4];
        byte[] c1 = c[..42], c2 = c[42..84], c3 = c[84..126], c4 = c[126..];

        using var dare = new DAREv1(k, encryption: true);
        dare.EncryptChunk(c1, p1);
        dare.EncryptChunk(c2, p2);
        dare.EncryptChunk(c3, p3);
        dare.EncryptChunk(c4, p4, finalChunk: true);
        Array.Clear(p);

        dare.Reinitialize(k, encryption: false);
        dare.DecryptChunk(p1, c1);
        // Chunk reordering/deletion
        Assert.ThrowsException<CryptographicException>(() => dare.DecryptChunk(p3, c3));
        dare.DecryptChunk(p2, c2);
        // Chunk duplication
        Assert.ThrowsException<CryptographicException>(() => dare.DecryptChunk(p2, c2));
        // Chunk swapping between streams with the same key (different nonces)
        c3[8]++;
        Assert.ThrowsException<CryptographicException>(() => dare.DecryptChunk(p3, c3));
        c3[8]--;
        // Stream truncation
        Assert.ThrowsException<CryptographicException>(() => dare.DecryptChunk(p3, c3, finalChunk: true));
    }

    [TestMethod]
    [DataRow(DAREv1.KeySize + 1, DAREv1.MinPlaintextChunkSize + DAREv1.HeaderSize + DAREv1.TagSize, DAREv1.MinPlaintextChunkSize)]
    [DataRow(DAREv1.KeySize - 1, DAREv1.MinPlaintextChunkSize + DAREv1.HeaderSize + DAREv1.TagSize, DAREv1.MinPlaintextChunkSize)]
    [DataRow(DAREv1.KeySize, DAREv1.MaxPlaintextChunkSize + DAREv1.HeaderSize + DAREv1.TagSize, DAREv1.MaxPlaintextChunkSize + 1)]
    [DataRow(DAREv1.KeySize, DAREv1.MinPlaintextChunkSize + DAREv1.HeaderSize + DAREv1.TagSize, DAREv1.MinPlaintextChunkSize - 1)]
    [DataRow(DAREv1.KeySize, DAREv1.MaxPlaintextChunkSize + DAREv1.HeaderSize + DAREv1.TagSize + 1, DAREv1.MaxPlaintextChunkSize)]
    [DataRow(DAREv1.KeySize, DAREv1.MinPlaintextChunkSize + DAREv1.HeaderSize + DAREv1.TagSize - 1, DAREv1.MinPlaintextChunkSize)]
    public void EncryptChunk_DecryptChunk_Invalid(int keySize, int ciphertextSize, int plaintextSize)
    {
        var k = new byte[keySize];
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];

        if (keySize != DAREv1.KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new DAREv1(k, encryption: true));
        }
        else {
            using var encryption = new DAREv1(k, encryption: true);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => encryption.EncryptChunk(c, p));

            using var decryption = new DAREv1(k, encryption: false);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => decryption.DecryptChunk(p, c));
        }
    }

    [TestMethod]
    public void SeekChunk_Invalid()
    {
        const uint finalChunkOffset = 4;
        var k = new byte[DAREv1.KeySize];

        using var dare = new DAREv1(k, encryption: false);

        // Need to decrypt final chunk first to detect stream truncation
        Assert.ThrowsException<CryptographicException>(() => dare.SeekChunk(finalChunkOffset, finalChunk: false));
        dare.SeekChunk(finalChunkOffset, finalChunk: true);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => dare.SeekChunk(finalChunkOffset + 1));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => dare.SeekChunk(finalChunkOffset, finalChunk: false));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => dare.SeekChunk(finalChunkOffset - 1, finalChunk: true));
    }

    [TestMethod]
    public void Stream_InvalidOperation()
    {
        var k = new byte[DAREv1.KeySize];
        var p = new byte[DAREv1.MinPlaintextChunkSize];
        var c = new byte[p.Length + DAREv1.HeaderSize + DAREv1.TagSize];

        using var encryption = new DAREv1(k, encryption: true);
        Assert.ThrowsException<InvalidOperationException>(() => encryption.DecryptChunk(p, c));
        Assert.ThrowsException<InvalidOperationException>(() => encryption.SeekChunk(1));
        encryption.EncryptChunk(c, p, finalChunk: true);
        Assert.ThrowsException<InvalidOperationException>(() => encryption.EncryptChunk(c, p));

        using var decryption = new DAREv1(k, encryption: false);
        Assert.ThrowsException<InvalidOperationException>(() => decryption.EncryptChunk(c, p));
        decryption.DecryptChunk(p, c, finalChunk: true);
        Assert.ThrowsException<InvalidOperationException>(() => decryption.DecryptChunk(p, c));
        Assert.ThrowsException<InvalidOperationException>(() => decryption.SeekChunk(1));
    }

    [TestMethod]
    public void Stream_Disposed()
    {
        var k = new byte[DAREv1.KeySize];
        var p = new byte[DAREv1.MinPlaintextChunkSize];
        var c = new byte[p.Length + DAREv1.HeaderSize + DAREv1.TagSize];

        var dare = new DAREv1(k, encryption: true);
        dare.Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() => dare.Reinitialize(k, encryption: false));
        Assert.ThrowsException<ObjectDisposedException>(() => dare.EncryptChunk(c, p));
        Assert.ThrowsException<ObjectDisposedException>(() => dare.DecryptChunk(p, c));
        Assert.ThrowsException<ObjectDisposedException>(() => dare.SeekChunk(1));
    }
}
