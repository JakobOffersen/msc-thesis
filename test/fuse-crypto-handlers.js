const assert = require("chai").assert
const { FuseHandlers, STREAM_CHUNK_SIZE } = require("../fuse-crypto-handlers")
const { join, resolve } = require("path")
const fs = require("fs/promises")
const fsFns = require("../fsFns.js")
const sodium = require("sodium-native")
const KeyProvider = require("../key-provider")

const tempDir = resolve("./tmp/")
const testFile = "test.txt"
const testFilePath = join(tempDir, testFile)

const keyProvider = new KeyProvider()
const handlers = new FuseHandlers(tempDir, keyProvider)

/* Helpers */
async function writeTestMessage(path, length) {
    const file = await fs.open(path, "w+")

    const message = Buffer.alloc(length)
    sodium.randombytes_buf(message)

    const header = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    const state = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES)
    sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, keyProvider.getKeyForPath(path))

    // Write header
    await file.write(header)

    // Write chunks
    let written = 0

    while (written < message.byteLength) {
        const toBeWritten = Math.min(STREAM_CHUNK_SIZE, length - written)

        const plaintext = message.subarray(written, written + toBeWritten)
        const ciphertext = Buffer.alloc(plaintext.byteLength + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
        const tag = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        const mlen = sodium.crypto_secretstream_xchacha20poly1305_push(state, ciphertext, plaintext, null, tag)

        written += toBeWritten

        // Write ciphertext
        await file.write(ciphertext)
    }

    await file.close()

    return message
}

// Uses the fuse handlers to open a file and read its contents
async function openAndRead(fileName, length, position = 0) {
    const fd = await handlers.open(fileName, 0)

    const readBuffer = Buffer.alloc(length)
    const readLength = await handlers.read(fileName, fd, readBuffer, length, position)

    await fsFns.close(fd)
    handlers.release(fileName, fd)

    return { readBuffer, readLength }
}

/* Test suite */

describe("fuse handlers", function () {
    beforeEach("setup test-file", async function () {
        // this also overwrites the (potentially) existing test-file
        // await fs.open(testFilePath, "w+")
    })

    afterEach("teardown test-file", async function () {
        try {
            await fs.rm(testFilePath)
        } catch (error) {}
    })

    /* These cases test reading an entire encrypted file in various sizes. */
    const sizes = [0, 1, 32, 128, STREAM_CHUNK_SIZE - 1, STREAM_CHUNK_SIZE, STREAM_CHUNK_SIZE + 1, 2 * STREAM_CHUNK_SIZE, 10000, 10 * STREAM_CHUNK_SIZE]

    sizes.forEach(size => {
        it(`reads a ${size} byte encrypted file`, async function () {
            const message = await writeTestMessage(testFilePath, size)
            const { readBuffer, readLength } = await openAndRead(testFile, message.byteLength, 0)

            assert.strictEqual(message.byteLength, readLength)
            assert.isTrue(Buffer.compare(message, readBuffer) === 0)
        })
    })

    /* This case tests reading an entire file through by performing several smaller reads. */
    it(`reads 5176 byte encrypted file in 8 byte sequences`, async function () {
        const size = 5176 // Must be divisible by sequenceSize
        const sequenceSize = 8

        const message = await writeTestMessage(testFilePath, size)

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
        handlers.release(testFile, fd)
    })

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
            const message = await writeTestMessage(testFilePath, size)
            const { readBuffer, readLength } = await openAndRead(testFile, length, start)

            const expectedMsg = message.subarray(start, start + length)

            assert.strictEqual(expectedMsg.byteLength, readLength)
            assert.isTrue(Buffer.compare(expectedMsg, readBuffer) === 0)
        })
    })

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
            const message = await writeTestMessage(testFilePath, size)
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

    // it("writing small file and then reading same file", async function () {
    //     const content = Buffer.from("hello world")
    //     let writeLength = await handlers.write(testFilePath, "fd", content, content.length, 0)
    //     assert.strictEqual(writeLength, content.length)

    //     const readBuffer = Buffer.alloc(content.length)
    //     const readLength = await handlers.read(testFilePath, "fd", readBuffer, content.length, 0)
    //     assert.strictEqual(readLength, content.length)
    //     assert.isTrue(Buffer.compare(content, readBuffer) === 0)
    // })

    // it("Writing file encrypts it", async function () {
    //     const content = Buffer.from("hello world")

    //     const writeLength = await handlers.write(testFilePath, "fd", content, content.length, 0)
    //     assert.strictEqual(writeLength, content.length)

    //     // compare 'content' with what was written to 'path'
    //     const data = await fs.readFile(testFilePath)
    //     assert.isFalse(Buffer.compare(content, data) === 0) // '.compare' returns 0 when the two buffers are equal
    //     assert.isFalse(Buffer.compare(content, data.slice(crypto.NONCE_LENGTH)) === 0) // verify that the bytes after the nonce are differnet from 'content
    // })

    // it("Appending to existing file and then reading it", async function () {
    //     const content1 = Buffer.from("hello world")
    //     const content2 = Buffer.from("many times!")
    //     const combined = Buffer.concat([content1, content2])
    //     let length

    //     length = await handlers.write(testFilePath, "fd", content1, content1.length, 0)
    //     assert.strictEqual(length, content1.length)

    //     const endOfFirstWrite = content1.length
    //     length = await handlers.write(testFilePath, "fd", content2, content2.length, endOfFirstWrite)
    //     assert.strictEqual(length, content2.length)

    //     const readBuffer = Buffer.alloc(content1.length + content2.length)
    //     length = await handlers.read(testFilePath, "fd", readBuffer, readBuffer.length, 0)
    //     assert.strictEqual(readBuffer.length, length)

    //     assert.isTrue(Buffer.compare(combined, readBuffer) === 0) // .compare returns 0 when the two buffers are equal
    // })

    // it("Writing to arbitrary position in existing file and then reading it", async function () {
    //     const initialContent = Buffer.from(
    //         "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
    //     )
    //     const contentToBeWritten = Buffer.from(
    //         "Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32."
    //     )
    //     const position = 87
    //     let length

    //     // write the initial content
    //     length = await handlers.write(testFilePath, "fd", initialContent, initialContent.length, 0)
    //     assert.strictEqual(length, initialContent.length)

    //     length = await handlers.write(testFilePath, "fd", contentToBeWritten, contentToBeWritten.length, position)
    //     assert.strictEqual(length, contentToBeWritten.length)

    //     const readBuffer = Buffer.alloc(initialContent.length + contentToBeWritten.length)
    //     length = await handlers.read(testFilePath, "fd", readBuffer, readBuffer.length, 0)
    //     assert.strictEqual(length, readBuffer.length)

    //     // compute the expected result
    //     const initialContentHeadSlice = initialContent.slice(0, position)
    //     const initialContentTailSlice = initialContent.slice(position)
    //     const expected = Buffer.concat([initialContentHeadSlice, contentToBeWritten, initialContentTailSlice])

    //     assert.isTrue(Buffer.compare(expected, readBuffer) === 0) // .compare returns 0 when the two buffers are equal
    // })

    // it("Writing to arbitrary position in existing file and then reading arbitrary slice of it", async function () {
    //     const initialContent = Buffer.from(
    //         "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
    //     )
    //     const contentToBeWritten = Buffer.from(
    //         "Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32."
    //     )
    //     const writePosition = 93
    //     const readPosition = 77
    //     const readLength = 496
    //     let length

    //     // write the initial content
    //     length = await handlers.write(testFilePath, "fd", initialContent, initialContent.length, 0)
    //     assert.strictEqual(length, initialContent.length)

    //     length = await handlers.write(testFilePath, "fd", contentToBeWritten, contentToBeWritten.length, writePosition)
    //     assert.strictEqual(length, contentToBeWritten.length)

    //     const readBuffer = Buffer.alloc(readLength)
    //     length = await handlers.read(testFilePath, "fd", readBuffer, readBuffer.length, readPosition)
    //     assert.strictEqual(length, readBuffer.length)

    //     // compute the expected result
    //     const initialContentHeadSlice = initialContent.slice(0, writePosition)
    //     const initialContentTailSlice = initialContent.slice(writePosition)
    //     const expectedFileContent = Buffer.concat([initialContentHeadSlice, contentToBeWritten, initialContentTailSlice])
    //     const expectedRead = expectedFileContent.slice(readPosition, readPosition + length)

    //     assert.isTrue(Buffer.compare(expectedRead, readBuffer) === 0) // .compare returns 0 when the two buffers are equal
    // })
})
