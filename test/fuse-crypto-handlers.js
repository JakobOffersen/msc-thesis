const assert = require("chai").assert
const { FuseHandlers } = require("../fuse/fuse-crypto-handlers")
const {
    STREAM_CHUNK_SIZE,
    STREAM_CIPHER_CHUNK_SIZE,
    MAC_LENGTH,
    NONCE_LENGTH,
    SIGNATURE_SIZE,
    CAPABILITY_TYPE_WRITE,
    CAPABILITY_TYPE_READ,
    CAPABILITY_TYPE_VERIFY
} = require("../constants")
const Keyring = require("../key-management/keyring")
const { join } = require("path")
const fs = require("fs/promises")
const fsFns = require("../fsFns.js")
const sodium = require("sodium-native")
const crypto = require("../crypto")
const { tmpdir } = require("os")

const tempDir = tmpdir()

const keyringPath = join(tempDir, "test.keyring")
const keyring = new Keyring(keyringPath)

const testFile = "/test.txt"
const testFilePath = join(tempDir, testFile)

const handlers = new FuseHandlers(tempDir, keyring)

/* Helpers */

/**
 * Creates a random message of the requested length. The message is encrypted and signed in the
 * same way the FUSE handlers would and then written to disk. The random message is returned.
 */
async function writeTestMessage(length) {
    // Create a random message
    const message = Buffer.alloc(length)
    sodium.randombytes_buf(message)

    // Find the appropriate keys and open a file handle
    const capabilities = await keyring.getCapabilitiesWithPath(testFile)
    const readCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_READ)
    const writeCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_WRITE)
    const file = await fs.open(testFilePath, "w+")

    const hasher = new crypto.Hasher()

    // Make room for the signature
    await file.write(Buffer.alloc(64))

    // Write chunks
    let written = 0

    while (written < message.byteLength) {
        const toBeWritten = Math.min(STREAM_CHUNK_SIZE, length - written)

        const plaintext = message.subarray(written, written + toBeWritten)

        const out = Buffer.alloc(NONCE_LENGTH + toBeWritten + MAC_LENGTH)

        // Create nonce and encrypt chunk
        const nonce = out.subarray(0, NONCE_LENGTH)
        sodium.randombytes_buf(nonce)

        const ciphertext = out.subarray(NONCE_LENGTH)
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, plaintext, null, null, nonce, readCapability.key)

        // Update hash state
        hasher.update(out)

        // Write nonce & ciphertext
        await file.write(out)
        written += toBeWritten
    }

    // Create signature
    const digest = hasher.final()

    const signature = crypto.signDetached(digest, writeCapability.key)
    await file.write(signature, 0, signature.byteLength, 0)
    await file.close()

    // Check that the signature was computed properly
    assert.isTrue(await checkSignature())

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

async function checkSignature() {
    // Find the appropriate keys and open a file handle
    const capabilities = await keyring.getCapabilitiesWithPath(testFile)
    const verifyCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_VERIFY)
    const file = await fs.open(testFilePath, "r")

    // Read signature from file
    const signature = Buffer.alloc(SIGNATURE_SIZE)
    await file.read(signature, 0, signature.byteLength, 0)

    const hasher = new crypto.Hasher()

    // Read chunks
    const fileLength = (await file.stat()).size - signature.byteLength
    let read = 0

    while (read < fileLength) {
        const toBeRead = Math.min(STREAM_CIPHER_CHUNK_SIZE, fileLength - read)

        const chunk = Buffer.alloc(toBeRead)
        await file.read(chunk, 0, toBeRead, read + signature.byteLength)

        // Update hash state
        hasher.update(chunk)

        read += toBeRead
    }

    await file.close()

    // Verify signature
    const digest = hasher.final()

    return crypto.verifyDetached(signature, digest, verifyCapability.key)
}

/* Test suite */

describe("fuse handlers", function () {
    before("setup keyring", async function () {
        await keyring.createNewCapabilitiesForRelativePath(testFile)
        const caps = await keyring.getCapabilitiesWithPath(testFile)
    })
    beforeEach("setup test-file", async function () {
        try {
            await fs.rm(testFilePath)
            // await fs.rm(keyringPath) // remove the previous test-key ring if any.
        } catch {}
    })

    afterEach("teardown test-file", async function () {
        try {
            await fs.rm(testFilePath)
            // await fs.rm(keyringPath) // remove the previous test-key ring if any.
        } catch {}
    })

    after("teardown keyring", async function () {
        try {
            await fs.rm(keyringPath) // remove the previous test-key ring if any.
        } catch {}
    })

    /* These cases test reading an entire encrypted file in various sizes. */
    const sizes = [0, 1, 32, 128, STREAM_CHUNK_SIZE - 1, STREAM_CHUNK_SIZE, STREAM_CHUNK_SIZE + 1, 2 * STREAM_CHUNK_SIZE, 10000, 10 * STREAM_CHUNK_SIZE]

    describe("reads entire files", function () {
        sizes.forEach(size => {
            it(`reads a ${size} byte file`, async function () {
                const message = await writeTestMessage(size)
                const readBuffer = await openAndRead(testFile, message.byteLength, 0)

                assert.strictEqual(message.byteLength, readBuffer.byteLength)
                assert.strictEqual(readBuffer.byteLength, size)
                assert.strictEqual(Buffer.compare(message, readBuffer), 0)
            })
        })
    })

    /* This case tests reading an entire file through by performing several smaller reads. */
    it(`reads 5176 byte encrypted file in 8 byte sequences`, async function () {
        const size = 5176 // Must be divisible by sequenceSize
        const sequenceSize = 8

        const message = await writeTestMessage(size)

        const readBuffer = Buffer.alloc(message.byteLength)
        const fd = await handlers.open(testFile, 0)
        let readLength = 0

        for (let pos = 0; pos < message.byteLength; pos += sequenceSize) {
            const sequence = readBuffer.subarray(pos, pos + sequenceSize)
            const seqLength = await handlers.read(testFile, fd, sequence, sequenceSize, pos)
            readLength += seqLength
        }

        await handlers.release(testFile, fd)
        await fsFns.close(fd)

        assert.strictEqual(message.byteLength, readLength)
        assert.strictEqual(Buffer.compare(message, readBuffer), 0)
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
                const message = await writeTestMessage(size)
                const readBuffer = await openAndRead(testFile, length, start)

                const expectedMsg = message.subarray(start, start + length)

                assert.strictEqual(Buffer.compare(expectedMsg, readBuffer), 0)
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
                const message = await writeTestMessage(size)
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
        const mode = 33188 // the mode FUSE uses when it calls our handler
        const cases3 = [1, 2, 4, 8, 64, 128, 512, 1000, 1024, 1234, 2048, 4096, 8192, 10000, 12000, 16384, 65536, 655360]

        cases3.forEach(writeSize => {
            it(`writes a ${writeSize} byte file`, async function () {
                const message = Buffer.alloc(writeSize)
                sodium.randombytes_buf(message)

                const fd = await handlers.create(testFile, mode)
                const bytesWritten = await handlers.write(testFile, fd, message, message.byteLength, 0)

                await fsFns.close(fd)
                await handlers.release(testFile, fd)

                const readBuffer = await openAndRead(testFile, message.byteLength, 0)

                assert.strictEqual(writeSize, bytesWritten)
                assert.strictEqual(writeSize, readBuffer.length)
                assert.strictEqual(Buffer.compare(message, readBuffer), 0)
                assert.isTrue(await checkSignature())
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

                const mode = 33188 // the mode FUSE uses when it calls our handler
                const fd = await handlers.create(testFile, mode)
                await handlers.write(testFile, fd, message, message.byteLength, 0)
                await handlers.write(testFile, fd, injection, injection.byteLength, position)

                await fsFns.close(fd)
                await handlers.release(testFile, fd)

                const readBuffer = await openAndRead(testFile, newMessage.byteLength, 0)

                assert.strictEqual(Buffer.compare(newMessage, readBuffer), 0)
                assert.isTrue(await checkSignature())
            })
        })
    })

    it("signs a file after creation", async function () {
        const mode = 33188 // the mode FUSE uses when it calls our handler
        await handlers.create(testFile, mode)

        assert.isTrue(await checkSignature())
    })

    describe("truncates files", function() {
        const cases5 = [
            [4096, 0],
            [4096, 10],
            [8192, 0],
            [8192, 4096],
            [8192, 7000],
            [0, 0]
        ]

        cases5.forEach(([size, truncateToSize]) => {
            it(`truncates a ${size} byte file to ${truncateToSize} bytes`, async function () {
                const message = await writeTestMessage(size)
                await handlers.truncate(testFile, truncateToSize)

                const remainingMessage = await openAndRead(testFile, truncateToSize, 0)

                assert.strictEqual(Buffer.compare(message.subarray(0, truncateToSize), remainingMessage), 0)
                assert.isTrue(await checkSignature())
            })
        })
    })
})
