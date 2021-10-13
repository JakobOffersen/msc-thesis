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