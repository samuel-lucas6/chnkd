using System.Security.Cryptography;
using static Chnkd.Secretstream;

namespace Chnkd.Tests;

[TestClass]
public class SecretstreamTests
{
    public static IEnumerable<object[]> EncryptParameters()
    {
        yield return
        [
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "50515253c0c1c2c3c4c5c6c7"
        ];
        yield return
        [
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
            ""
        ];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(24, HeaderSize);
        Assert.AreEqual(32, KeySize);
        Assert.AreEqual(17, TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void EncryptChunk_DecryptChunk_SingleChunk_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[HeaderSize]; h.Clear();
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> ad = Convert.FromHexString(associatedData);
        Span<byte> c = stackalloc byte[p.Length + TagSize];

        using var secretstream = new Secretstream(h, k, encryption: true);
        Assert.IsFalse(h.SequenceEqual(new byte[h.Length]));
        secretstream.EncryptChunk(c, p, ad, ChunkFlag.Final);
        p.Clear();

        secretstream.Reinitialize(h, k, encryption: false);
        var chunkFlag = secretstream.DecryptChunk(p, c, ad);
        Assert.AreEqual(ChunkFlag.Final, chunkFlag);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void EncryptChunk_DecryptChunk_MultipleChunks_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];

        Span<byte> c = stackalloc byte[p.Length + TagSize * 4];
        Span<byte> c1 = c[..(p1.Length + TagSize)], c2 = c.Slice(c1.Length, p2.Length + TagSize);
        Span<byte> c3 = c.Slice(c1.Length + c2.Length, p3.Length + TagSize), c4 = c[^(p4.Length + TagSize)..];

        using var secretstream = new Secretstream(h, k, encryption: true);
        secretstream.EncryptChunk(c1, p1, ad, ChunkFlag.Message);
        secretstream.EncryptChunk(c2, p2, ChunkFlag.Boundary);
        secretstream.EncryptChunk(c3, p3, ChunkFlag.Rekey);
        secretstream.EncryptChunk(c4, p4, ChunkFlag.Final);
        p.Clear();

        secretstream.Reinitialize(h, k, encryption: false);
        var chunkFlag = secretstream.DecryptChunk(p1, c1, ad);
        Assert.AreEqual(ChunkFlag.Message, chunkFlag);
        chunkFlag = secretstream.DecryptChunk(p2, c2);
        Assert.AreEqual(ChunkFlag.Boundary, chunkFlag);
        chunkFlag = secretstream.DecryptChunk(p3, c3);
        Assert.AreEqual(ChunkFlag.Rekey, chunkFlag);
        chunkFlag = secretstream.DecryptChunk(p4, c4);
        Assert.AreEqual(ChunkFlag.Final, chunkFlag);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void DecryptChunk_SingleChunk_Tampered(string key, string plaintext, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "h", new byte[HeaderSize] },
            { "k", Convert.FromHexString(key) },
            { "c", new byte[p.Length + TagSize] },
            { "ad", Convert.FromHexString(associatedData) }
        };

        using var secretstream = new Secretstream(parameters["h"], parameters["k"], encryption: true);
        secretstream.EncryptChunk(parameters["c"], p, parameters["ad"], ChunkFlag.Final);

        // Wrong parameters/stream modification
        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            secretstream.Reinitialize(parameters["h"], parameters["k"], encryption: false);
            Assert.ThrowsException<CryptographicException>(() => secretstream.DecryptChunk(p, parameters["c"], parameters["ad"]));
            param[0]--;
        }
        // Incorrect rekey
        secretstream.Reinitialize(parameters["h"], parameters["k"], encryption: false);
        secretstream.Rekey();
        Assert.ThrowsException<CryptographicException>(() => secretstream.DecryptChunk(p, parameters["c"], parameters["ad"]));
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(EncryptParameters), DynamicDataSourceType.Method)]
    public void DecryptChunk_MultiChunk_Tampered(string key, string plaintext, string associatedData)
    {
        var h = new byte[HeaderSize];
        var k = Convert.FromHexString(key);
        var ad = Convert.FromHexString(associatedData);

        var p = Convert.FromHexString(plaintext);
        byte[] p1 = p[..10], p2 = p[10..20], p3 = p[20..30], p4 = p[30..];

        var c = new byte[p.Length + TagSize * 4];
        byte[] c1 = c[..27], c2 = c[27..54], c3 = c[54..81], c4 = c[81..];

        using var secretstream = new Secretstream(h, k, encryption: true);
        secretstream.EncryptChunk(c1, p1, ad);
        secretstream.EncryptChunk(c2, p2);
        secretstream.EncryptChunk(c3, p3);
        secretstream.EncryptChunk(c4, p4, ChunkFlag.Final);
        Array.Clear(p);

        for (int i = 0; i < 2; i++) {
            secretstream.Reinitialize(h, k, encryption: false);
            secretstream.DecryptChunk(p1, c1, ad);
            switch (i) {
                case 0:
                    // Chunk reordering/deletion
                    Assert.ThrowsException<CryptographicException>(() => secretstream.DecryptChunk(p3, c3));
                    break;
                case 1:
                    // Chunk duplication
                    Assert.ThrowsException<CryptographicException>(() => secretstream.DecryptChunk(p1, c1, ad));
                    break;
            }
        }
    }

    [TestMethod]
    [DataRow(HeaderSize + 1, KeySize, TagSize, 0)]
    [DataRow(HeaderSize - 1, KeySize, TagSize, 0)]
    [DataRow(HeaderSize, KeySize + 1, TagSize, 0)]
    [DataRow(HeaderSize, KeySize - 1, TagSize, 0)]
    [DataRow(HeaderSize, KeySize, TagSize + 1, 0)]
    [DataRow(HeaderSize, KeySize, TagSize - 1, 0)]
    public void EncryptChunk_DecryptChunk_Invalid(int headerSize, int keySize, int ciphertextSize, int plaintextSize)
    {
        var h = new byte[headerSize];
        var k = new byte[keySize];
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];

        if (headerSize != HeaderSize || keySize != KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new Secretstream(h, k, encryption: true));
        }
        else {
            using var encryption = new Secretstream(h, k, encryption: true);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => encryption.EncryptChunk(c, p));

            using var decryption = new Secretstream(h, k, encryption: false);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => decryption.DecryptChunk(p, c));
        }
    }

    [TestMethod]
    public void Secretstream_InvalidOperation()
    {
        var h = new byte[HeaderSize];
        var k = new byte[KeySize];
        var p = new byte[h.Length];
        var c = new byte[p.Length + TagSize];

        using var encryption = new Secretstream(h, k, encryption: true);
        Assert.ThrowsException<InvalidOperationException>(() => encryption.DecryptChunk(p, c));
        encryption.EncryptChunk(c, p, ChunkFlag.Final);
        Assert.ThrowsException<InvalidOperationException>(() => encryption.EncryptChunk(c, p));
        Assert.ThrowsException<InvalidOperationException>(() => encryption.Rekey());

        using var decryption = new Secretstream(h, k, encryption: false);
        Assert.ThrowsException<InvalidOperationException>(() => decryption.EncryptChunk(c, p));
        decryption.DecryptChunk(p, c);
        // Stream extension
        Assert.ThrowsException<InvalidOperationException>(() => decryption.DecryptChunk(p, c));
        Assert.ThrowsException<InvalidOperationException>(() => decryption.Rekey());
    }

    [TestMethod]
    public void Secretstream_Disposed()
    {
        var h = new byte[HeaderSize];
        var k = new byte[KeySize];
        var p = new byte[h.Length];
        var c = new byte[p.Length + TagSize];

        var secretstream = new Secretstream(h, k, encryption: true);
        secretstream.Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() => secretstream.Reinitialize(h, k, encryption: false));
        Assert.ThrowsException<ObjectDisposedException>(() => secretstream.EncryptChunk(c, p));
        Assert.ThrowsException<ObjectDisposedException>(() => secretstream.DecryptChunk(p, c));
        Assert.ThrowsException<ObjectDisposedException>(() => secretstream.Rekey());
    }
}
