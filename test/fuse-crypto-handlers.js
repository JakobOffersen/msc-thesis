const assert = require("chai").assert
const { FuseHandlers } = require("../fuse/fuse-crypto-handlers")
const { STREAM_CHUNK_SIZE, STREAM_CIPHER_CHUNK_SIZE, SIGNATURE_SIZE } = require("../constants")
const KeyRing = require("../key-management/keyring")
const { join, resolve } = require("path")
const fs = require("fs/promises")
const fsFns = require("../fsFns.js")
const sodium = require("sodium-native")
const crypto = require("../crypto")
const { createHash } = require("crypto")

const tempDir = resolve("./tmp/")
const keyringPath = join(tempDir, "test.keyring")

const testFile = "/test.txt"
const testFilePath = join(tempDir, testFile)

const keyring = new KeyRing(keyringPath)
const handlers = new FuseHandlers(tempDir, keyring)

/* Helpers */
// TODO: Ændr denne til ikke at benytte FUSE?
async function writeTestMessage(path, length) {
    const mode = 33188 // the mode FUSE uses when it calls our handler
    let fd = await handlers.create(path, mode)

    const message = Buffer.alloc(length)
    sodium.randombytes_buf(message)
    // Write chunks
    let written = 0

    while (written < message.byteLength) {
        const toBeWritten = Math.min(STREAM_CHUNK_SIZE, length - written)

        const plaintext = message.subarray(written, written + toBeWritten)

        await handlers.write(path, fd, plaintext, toBeWritten, written)

        written += toBeWritten
    }

    await handlers.release(path, fd)
    await fsFns.close(fd)

    return message
}

// Uses the fuse handlers to open a file and read its contents
async function openAndRead(path, length, position = 0) {
    const fd = await handlers.open(path, "r")

    const message = Buffer.alloc(length)

    let read = 0

    while (read < message.byteLength) {
        const toBeRead = Math.min(STREAM_CHUNK_SIZE, length - read)

        const plaintext = message.subarray(read, read + toBeRead)

        await handlers.read(path, fd, plaintext, toBeRead, read + position)

        read += toBeRead
    }

    await handlers.release(path, fd)
    await fsFns.close(fd)

    return message
}

/* Test suite */

describe("fuse handlers", function () {
    before("setup keyring", async function () {
        try {
            await fs.rm(keyringPath) // remove the previous test-key ring if any.
        } catch {}
    })
    beforeEach("setup test-file", async function () {
        try {
            await fs.rm(testFilePath)
            await fs.rm(keyringPath) // remove the previous test-key ring if any.
        } catch {}
    })

    afterEach("teardown test-file", async function () {
        try {
            await fs.rm(testFilePath)
            await fs.rm(keyringPath) // remove the previous test-key ring if any.
        } catch {}
    })

    after("teardown keyring", async function () {
        try {
            await fs.rm(keyringPath) // remove the previous test-key ring if any.
        } catch {}
    })

    /* These cases test reading an entire encrypted file in various sizes. */
    const sizes = [0, 1, 32, 128, STREAM_CHUNK_SIZE - 1, STREAM_CHUNK_SIZE, STREAM_CHUNK_SIZE + 1, 2 * STREAM_CHUNK_SIZE, 10000, 10 * STREAM_CHUNK_SIZE]

    describe("writes and reads entire files", function () {
        sizes.forEach(size => {
            it(`writes and reads a ${size} byte file`, async function () {
                const message = await writeTestMessage(testFile, size)
                const readBuffer = await openAndRead(testFile, message.byteLength, 0)

                assert.strictEqual(message.length, readBuffer.length)
                assert.strictEqual(message.length, size)
                assert.isTrue(Buffer.compare(message, readBuffer) === 0)
            })
        })
    })

    /* This case tests reading an entire file through by performing several smaller reads. */
    it(`reads 5176 byte encrypted file in 8 byte sequences`, async function () {
        const size = 5176 // Must be divisible by sequenceSize
        const sequenceSize = 8

        const message = await writeTestMessage(testFile, size)

        const readBuffer = Buffer.alloc(message.byteLength)
        const fd = await handlers.open(testFile, 0)
        let readLength = 0

        for (let pos = 0; pos < message.byteLength; pos += sequenceSize) {
            const sequence = readBuffer.subarray(pos, pos + sequenceSize)
            const seqLength = await handlers.read(testFile, fd, sequence, sequenceSize, pos)
            readLength += seqLength
        }

        assert.strictEqual(message.byteLength, readLength)
        assert.isTrue(Buffer.compare(message, readBuffer) === 0)

        await fsFns.close(fd)
        await handlers.release(testFile, fd)
    })

    describe("reads from arbitrary positions across chunk boundaries in files of different sizes", function () {
        /* These cases test reading from arbitrary locations in the file and across chunk boundaries. */
        const cases = [
            [1024, 0, 512],
            [1024, 1, 2],
            [1024, 256, 768],
            [1024, 0, 1024],
            [1024, 10, 20],
            [1024, 1000, 24],
            [1024, 367, 124],
            [4064, 1, 3000],
            [4080, 1, 3000]
        ]

        cases.forEach(([size, start, length]) => {
            it(`reads ${length} bytes from position ${start} within a ${size} byte file`, async function () {
                const message = await writeTestMessage(testFile, size)
                const readBuffer = await openAndRead(testFile, length, start)

                const expectedMsg = message.subarray(start, start + length)

                assert.isTrue(Buffer.compare(expectedMsg, readBuffer) === 0)
            })
        })
    })

    describe("reads from arbitrary, non-sequential positions in a file", function () {
        /* These cases test skipping (reading from arbitrary, non-sequential positions) */
        const cases2 = [
            [0, 4096], // Chunk 0
            [0, 4097], // Chunks 0, 1
            [0, 4097, 8193, 12289], // Chunks 0-3
            [0, 5000, 10, 6000], // Chunks 0, 1, 0, 1
            [5500], // Chunk 1
            [14000], // Chunk 3
            [12289, 8193, 4097, 0], // Chunks 3, 2, 1, 0
            [5000, 13000, 9000, 1000], // Chunks 1, 3, 2, 0
            [16383, 0] // Chunks 3, 0
        ]

        cases2.forEach(positions => {
            it(`reads bytes ${positions} from a 16384 byte file`, async function () {
                const size = 16384
                const message = await writeTestMessage(testFile, size)
                const expectedMessage = Buffer.from(positions.map(i => message.readUInt8(i)))

                const readBuffer = Buffer.alloc(expectedMessage.byteLength)
                const fd = await handlers.open(testFile, 0)

                for (const [index, position] of positions.entries()) {
                    const window = readBuffer.subarray(index, index + 1)
                    const length = await handlers.read(testFile, fd, window, 1, position)
                    assert.strictEqual(length, 1)
                }

                assert.isTrue(Buffer.compare(expectedMessage, readBuffer) === 0)

                await fsFns.close(fd)
                handlers.release(testFile, fd)
            })
        })
    })

    describe("writes files of different sizes", function () {
        /** Write handler tests **/
        const FILE_WRITE_FLAGS = 1538 // fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_RDWR
        const cases3 = [1, 2, 4, 8, 64, 128, 512, 1000, 1024, 1234, 2048, 4096, 8192, 10000, 12000, 16384, 65536, 655360]

        cases3.forEach(writeSize => {
            it(`writes a ${writeSize} byte file`, async function () {
                const message = Buffer.alloc(writeSize)
                sodium.randombytes_buf(message)

                const mode = 33188 // the mode FUSE uses when it calls our handler
                const fd = await handlers.create(testFile, mode)
                const bytesWritten = await handlers.write(testFile, fd, message, message.byteLength, 0)

                await fsFns.close(fd)
                await handlers.release(testFile, fd)

                const readBuffer = await openAndRead(testFile, message.byteLength, 0)

                assert.strictEqual(writeSize, bytesWritten)
                assert.strictEqual(writeSize, readBuffer.length)
                assert.strictEqual(Buffer.compare(message, readBuffer), 0)
            })
        })
    })

    describe("writes entire file followed by inserting window at arbitrary position with arbitrary size", function () {
        const cases4 = [
            [4096, 200, 0],
            [4096, 200, 2048],
            [4096, 200, 4096],
            [8192, 100, 0],
            [8192, 100, 4096],
            [8192, 100, 6000],
            [8192, 8192, 7000],
            [8192, 8192, 8192],
            [65536, 1, 0],
            [65536, 1, 1],
            [65536, 1, 20000],
            [65536, 1, 65536]
        ]
        cases4.forEach(([size, writeSize, position]) => {
            it(`writes ${size} byte file and inserts ${writeSize} byte(s) at position ${position}`, async function () {
                const message = Buffer.alloc(size)
                sodium.randombytes_buf(message)

                const injection = Buffer.alloc(writeSize)
                sodium.randombytes_buf(injection)

                const head = message.subarray(0, position)
                const remaining = position + injection.byteLength > message.byteLength ? Buffer.alloc(0) : message.subarray(position + injection.byteLength)
                const newMessage = Buffer.concat([head, injection, remaining])

                const mode = 33188 // the mode FUSE uses when it calls our handler //TODO: Refactor all 'modes' into one constant with documentation as for why this mode is needed
                const fd = await handlers.create(testFile, mode)
                await handlers.write(testFile, fd, message, message.byteLength, 0)
                await handlers.write(testFile, fd, injection, injection.byteLength, position)

                await fsFns.close(fd)
                await handlers.release(testFile, fd)

                const readBuffer = await openAndRead(testFile, newMessage.byteLength, 0)

                assert.strictEqual(Buffer.compare(newMessage, readBuffer), 0)
            })
        })
    })

    describe("signature matches file content after every write", function () {
        const mode = 33188 // the mode FUSE uses when it calls our handler

        async function readSignature(path) {
            const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
            const fd = await fsFns.open(path, "r")
            await fsFns.read(fd, signature, 0, signature.length, 0)
            return signature
        }

        async function readWindow(path, startPosition, size) {
            const window = Buffer.alloc(size)
            const fd = await fsFns.open(path, "r")
            await fsFns.read(fd, window, 0, window.length, startPosition)
            return window
        }

        it("signature is added on file creation", async function () {
            const hash = createHash("sha256")
            await handlers.create(testFile, mode)

            const verifyCapability = await keyring.getCapabilityWithPathAndType(testFile, "verify")
            const verifyKey = verifyCapability.key
            const expectedMessage = Buffer.from(hash.digest(), "hex") // we expect the hash to be on the empty string

            const signature = await readSignature(testFilePath)

            const verified = crypto.verifyDetached(signature, expectedMessage, verifyKey)
            assert.isTrue(verified)
        })

        it("updates signature of content-hash after each write", async function () {
            const size = 2 * STREAM_CHUNK_SIZE
            const hash = createHash("sha256")

            const fd = await handlers.create(testFile, mode)
            const verifyCapability = await keyring.getCapabilityWithPathAndType(testFile, "verify")
            const verifyKey = verifyCapability.key

            const message = Buffer.alloc(size)
            sodium.randombytes_buf(message)

            for (let chunk = 0; chunk < 2; chunk++) {
                const position = chunk * STREAM_CHUNK_SIZE
                const half = message.subarray(position, position + STREAM_CHUNK_SIZE)
                await handlers.write(testFile, fd, half, half.length, position)
                const signature = await readSignature(testFilePath)
                const offset = SIGNATURE_SIZE // avoid reading the signare since the signature should not be a part of the hash of the content to be signed
                const window = await readWindow(testFilePath, offset + chunk * STREAM_CIPHER_CHUNK_SIZE, STREAM_CIPHER_CHUNK_SIZE)
                hash.update(window)
                const digest = hash.copy().digest("hex") // make a copy of the hash to allow it to continue rolling
                const verified = crypto.verifyDetached(signature, Buffer.from(digest, "hex"), verifyKey)

                assert.isTrue(verified)
            }
        })
    })
})
