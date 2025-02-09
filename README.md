# CHNKD
CHNKD is a library that provides incremental APIs for different approaches to [stream encryption](https://eprint.iacr.org/2015/189), which I prefer to call *chunked encryption* because it's about encrypting in chunks. Supported constructions include:

- [x] [STREAM](https://eprint.iacr.org/2015/189)
- [ ] [CHAIN](https://eprint.iacr.org/2015/189)
- [x] [crypto_secretstream_xchacha20poly1305](https://doc.libsodium.org/secret-key_cryptography/secretstream) (however, use [Geralt](https://www.geralt.xyz/authenticated-encryption/stream-and-file-encryption) instead)
- [x] crypto_secretstream_aegis256 POC (see [here](https://github.com/samuel-lucas6/crypto-secretstream-aegis256))
- [x] [monostream](https://monocypher.org/manual/aead)
- [ ] [DARE](https://github.com/minio/sio)

Note that there may be variants of the above using different algorithms/formats. For example, [age](https://github.com/C2SP/C2SP/blob/main/age.md), [Tink](https://developers.google.com/tink/wire-format#streaming_aead), and [Miscreant](https://github.com/miscreant/meta/wiki/STREAM) have implemented STREAM variants. There's little value in implementing every single variant, and my algorithm of choice is [AEGIS-256](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead) where possible.
