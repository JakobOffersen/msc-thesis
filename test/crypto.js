const assert = require('chai').assert
const crypto = require('../crypto')

describe("Crypto.js", function() {
    describe("#hash(input)", function() {
        it("input must be of type Buffer", function() {
            const input = Buffer.from("hello world")
            const output = crypto.hash(input)
            assert.isTrue(Buffer.isBuffer(input))
            assert.isNotNull(output)
        })

        it("throws error if input is not of type Buffer", function() {
            const input = "plain message"
            assert.throws(() => { crypto.hash(input) })
        })

        it("output is of type Buffer", function() {
            const input = Buffer.from("input")
            const output = crypto.hash(input)
            assert.isTrue(Buffer.isBuffer(output))
        })
    })
    describe("#makeNonce()", function() {
        it("should return a fresh nonce at each function-call", function() {
            const n1 = crypto.makeNonce()
            const n2 = crypto.makeNonce()
            assert.notEqual(n1, n2)
        })

        it("should be of type Buffer", function() {
            const n1 = crypto.makeNonce()
            assert.isTrue(Buffer.isBuffer(n1))
        })

        it("should be of length 24", function() {
            const n1 = crypto.makeNonce()
            assert.equal(n1.length, 24)
        })
    })

    describe("Symmetric Cryptography", function() {
        describe("#makeSymmetricKey()", function() {
            it("should return a fresh key at each function-call", function() {
                const k1 = crypto.makeSymmetricKey()
                const k2 = crypto.makeSymmetricKey()
                assert.notEqual(k1, k2)
            })

            it("returns type Buffer", function() {
                const k1 = crypto.makeSymmetricKey()
                assert.isTrue(Buffer.isBuffer(k1))
            })

            it("returns Buffer of length 32", function() {
                const k1 = crypto.makeSymmetricKey()
                assert.equal(k1.length, 32)
            })
        })

        describe("#encrypt(message, key)", function() {
            it("message can be type string", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k)
                assert.isString(m)
                assert.isNotNull(c)
                assert.isNotEmpty(c)
            })

            it("message can be type Buffer", function() {
                const m = Buffer.from("hello world", 'utf-8')
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k)
                assert.isTrue(Buffer.isBuffer(m))
                assert.isNotNull(c)
                assert.isNotEmpty(c)
            })

            it("key is type Buffer", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k)
                assert.isTrue(Buffer.isBuffer(k))
                assert.isNotNull(c)
                assert.isNotEmpty(c)
            })

            it("returns type Buffer", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k)
                assert.isTrue(Buffer.isBuffer(c))
            })

            it("key is length 32", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const tooShortKey = Buffer.alloc(31, "this is a random key string that is filled into the allocated 31 bytes")
                const tooLongKey = Buffer.alloc(33, "this is a random key string that is filled into the allocated 33 bytes")

                assert.equal(k.length, 32)
                assert.notEqual(tooShortKey.length, 32)
                assert.notEqual(tooLongKey.length, 32)

                assert.doesNotThrow(() => { crypto.encrypt(m, k) })
                assert.throws(() => { crypto.encrypt(m, tooShortKey)})
                assert.throws(() => { crypto.encrypt(m, tooLongKey) })
            })

            it("should create a new cipher every time", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c1 = crypto.encrypt(m, k)
                const c2 = crypto.encrypt(m, k)
                assert.notEqual(c1, c2)
            })
        })

        describe("#decrypt(cipher, key)", function() {
            it("cipher must be type Buffer", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k)
                const _ = crypto.decrypt(c, k)
                assert.isTrue(Buffer.isBuffer(c))
            })

            it("key must be type Buffer", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k)
                const decrypted = crypto.decrypt(c, k)

                assert.isTrue(Buffer.isBuffer(k))
                assert.isNotNull(decrypted)
            })

            it("key must be length 32", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k)
                const tooShortKey = Buffer.alloc(31, "this is a random key string that is filled into the allocated 31 bytes")
                const tooLongKey = Buffer.alloc(33, "this is a random key string that is filled into the allocated 33 bytes")

                assert.equal(k.length, 32)
                assert.notEqual(tooShortKey.length, 32)
                assert.notEqual(tooLongKey.length, 32)

                assert.doesNotThrow(() => { crypto.decrypt(c, k) })
                assert.throws(() => { crypto.decrypt(c, tooShortKey) })
                assert.throws(() => { crypto.decrypt(c, tooLongKey) })
            })

            it("returns type Buffer", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k)
                const decrypted = crypto.decrypt(c, k)

                assert.isTrue(Buffer.isBuffer(decrypted))
            })

        })

        describe("encryption & decryption", function() {

            it("encrypt then decrypt gives the original plain message", function() {
                const m = "hello world"
                const k = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m,k)
                const decrypted = crypto.decrypt(c, k)
                const mBuffer = Buffer.from(m)
                assert.equal(mBuffer.compare(decrypted), 0) // .compare returns 0 iff the two buffers are equal
            })

            it("decrypting with wrong key returns 'null'", function() {
                const m = "hello world"
                const k1 = crypto.makeSymmetricKey()
                const k2 = crypto.makeSymmetricKey()
                const c = crypto.encrypt(m, k1)
                const decrypted = crypto.decrypt(c, k2)
                assert.isNull(decrypted)
            })
        })
    })

    describe("Assymmetric Cryptography", function() {
        describe("#makeKeyPair()", function() {
            it("returns { sk, pk } of type { Buffer, Buffer } with sizes { 64, 32 }", function() {
                const { sk, pk } = crypto.makeKeyPair()
                assert.isTrue(Buffer.isBuffer(sk))
                assert.isTrue(Buffer.isBuffer(pk))
                assert.equal(sk.length, 64)
                assert.equal(pk.length, 32)
            })

            it("returns a fresh key pair at each function-call", function() {
                const pair1 = crypto.makeKeyPair()
                const pair2 = crypto.makeKeyPair()
                assert.notEqual(pair1.sk, pair2.sk)
                assert.notEqual(pair1.pk, pair2.pk)
            })
        })

        describe("#sign(message, sk)", function() {
            it("message must be type Buffer", function() {
                const m1 = Buffer.from("hello world")
                const m2 = "hello world"
                const { sk, _ } = crypto.makeKeyPair()

                assert.isTrue(Buffer.isBuffer(m1))
                assert.doesNotThrow(() => {crypto.sign(m1, sk) })
                assert.throws(() => { crypto.sign(m2, sk) })
            })

            it("key must be type Buffer of size 64", function() {
                const m = Buffer.from("hello world")
                const { sk, _ } = crypto.makeKeyPair()
                const tooShortSignKey = Buffer.alloc(63, "filling")
                const tooLongSignKey = Buffer.alloc(65, "filling")

                assert.isTrue(Buffer.isBuffer(sk))
                assert.equal(sk.length, 64)
                assert.notEqual(tooShortSignKey, 64)
                assert.notEqual(tooLongSignKey, 64)

                assert.doesNotThrow(() => { crypto.sign(m, sk) })
                assert.throws(() => { crypto.sign(m, tooShortSignKey) })
                assert.throws(() => { crypto.sign(m, tooLongSignKey) })
            })

            it("returns type Buffer of size 64", function() {
                const m = Buffer.from("hello world")
                const { sk, _ } = crypto.makeKeyPair()
                const signature = crypto.sign(m, sk)
                assert.isTrue(Buffer.isBuffer(signature))
                assert.equal(signature.length, 64)
            })
        })

        describe("#verify(signature, pk)", function() {
            it("signature must be buffer of size 64", function() {
                const m = Buffer.from("hello world")
                const { sk, pk } = crypto.makeKeyPair()
                const sig = crypto.sign(m, sk)
                const fakeSig = "sig"

                assert.doesNotThrow(() => { crypto.verify(sig, m, pk) })
                assert.throws(() => { crypto.verify(fakeSig, m, pk) })
            })

            it("pk must be Buffer of size 64", function() {
                const m = Buffer.from("hello world")
                const { sk, pk } = crypto.makeKeyPair()
                const pkTooShort = Buffer.alloc(31, "pk")
                const pkTooLong = Buffer.alloc(33, "pk")

                const sig = crypto.sign(m, sk)

                assert.doesNotThrow(() => { crypto.verify(sig, m, pk) })
                assert.throws(() => { crypto.verify(sig, m, pkTooShort) })
                assert.throws(() => { crypto.verify(sig, m, pkTooLong) })
            })

            it("returns true iff signature is issued with corresponding secret key for passed public key", function() {
                const m = Buffer.from("hello world")
                const { sk, pk } = crypto.makeKeyPair()
                const sig = crypto.sign(m, sk)

                const result = crypto.verify(sig, m, pk)
                assert.isTrue(result)
            })

            it("returns false iff signature is issued with other secret key than passed public key", function() {
                const m = Buffer.from("hello world")
                const { sk, _ } = crypto.makeKeyPair()
                const otherPair = crypto.makeKeyPair()
                const sig = crypto.sign(m, sk)

                const result = crypto.verify(sig, m, otherPair.pk)
                assert.isFalse(result)
            })
        })
    })
})