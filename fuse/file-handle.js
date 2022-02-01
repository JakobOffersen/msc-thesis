const { TYPE_READ, TYPE_WRITE, TYPE_VERIFY } = require("./../key-management/config")
const sodium = require("sodium-native")
const fsFns = require("../fsFns.js")
const { hasSignature, TOTAL_SIGNATURE_SIZE } = require("./file-signer")
const { createReadStream, statSync, readFileSync } = require("fs")
const { basename } = require("path")

// The maximum size of a message appended to the stream
// Every chunk, except for the last, in the stream is of this size.
const STREAM_CHUNK_SIZE = 4096

// The maximum size of a chunk after it has been encrypted.
const STREAM_CIPHER_CHUNK_SIZE = STREAM_CHUNK_SIZE + sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES

class FileHandle {
    /**
     * TODO: Fix params documentation
     * @param {number} fd
     * @param {Buffer} key
     */
    constructor({ fd, path, capabilities }) {
        this.fd = fd
        this.path = path

        this.readCapability = capabilities.find(cap => cap.type === TYPE_READ) //TODO: refactor to not depend on TYPE_READ
        this.writeCapability = capabilities.find(cap => cap.type === TYPE_WRITE)
        this.verifyCapability = capabilities.find(cap => cap.type === TYPE_VERIFY)
    }

    async #getPlainFileSize() {
        return this.#plaintextLengthFromCiphertextAndSignatureSize((await fsFns.fstat(this.fd)).size)
    }

    #ciphertextChunkIndex(plaintextPosition) {
        return Math.floor(plaintextPosition / STREAM_CHUNK_SIZE)
    }

    // Returns the starting position within the ciphertext of a given chunk
    #chunkPosition(index) {
        return index * STREAM_CIPHER_CHUNK_SIZE
    }

    #plaintextLengthFromCiphertextAndSignatureSize(ciphertextAndSignatureBytes) {
        return this.#plaintextLengthFromCiphertextSize(ciphertextAndSignatureBytes - TOTAL_SIGNATURE_SIZE)
    }

    #plaintextLengthFromCiphertextSize(ciphertextBytes) {
        const blockCount = Math.ceil(ciphertextBytes / STREAM_CIPHER_CHUNK_SIZE)
        const tagSizes = blockCount * (sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES)

        return ciphertextBytes - tagSizes
    }

    async #readChunks(from, to) {
        //TODO: When reading from start to finish, we load two chunks every time, but J thinks we only need to load one. Check if this is the case
        let fileSize = (await fsFns.fstat(this.fd)).size

        const start = this.#chunkPosition(from) + TOTAL_SIGNATURE_SIZE
        // The last chunk of the file may be less than full size.
        const end = Math.min(this.#chunkPosition(to) + STREAM_CIPHER_CHUNK_SIZE + TOTAL_SIGNATURE_SIZE, fileSize)
        const length = end - start
        const ciphertext = Buffer.alloc(length)

        await fsFns.read(this.fd, ciphertext, 0, length, start)

        return ciphertext
    }

    async read(buffer, length, position) {
        if (length === 0 || !this.readCapability) return 0

        // Determine which chunks in the ciphertext stream the read request covers.
        const startChunkIndex = this.#ciphertextChunkIndex(position)
        const endChunkIndex = this.#ciphertextChunkIndex(position + length)

        // Read ciphertext from disk
        const ciphertext = await this.#readChunks(startChunkIndex, endChunkIndex)

        // Decrypt chunks
        const plaintextLength = this.#plaintextLengthFromCiphertextSize(ciphertext.byteLength)
        const plaintext = Buffer.alloc(plaintextLength)

        const chunks = Math.ceil(plaintextLength / STREAM_CHUNK_SIZE)

        for (let chunk = 0; chunk < chunks; chunk++) {
            const chunkStart = chunk * STREAM_CIPHER_CHUNK_SIZE
            const chunkLength = Math.min(STREAM_CIPHER_CHUNK_SIZE, ciphertext.byteLength - chunkStart)

            const inBuffer = ciphertext.subarray(chunkStart, chunkStart + chunkLength)

            const nonce = inBuffer.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
            const encrypted = inBuffer.subarray(sodium.crypto_secretbox_NONCEBYTES)

            const outStart = chunk * STREAM_CHUNK_SIZE
            const outEnd = outStart + this.#plaintextLengthFromCiphertextSize(chunkLength)
            const outBuffer = plaintext.subarray(outStart, outEnd)
            const res = sodium.crypto_secretbox_open_easy(outBuffer, encrypted, nonce, this.readCapability.key)
            if (!res) throw new Error("Decryption failed")
        }

        // Determine what we should return from the plaintext
        // (i.e. we might have to discard some of the head and/or tail of the plaintext to satisfy the request)
        const windowStart = position % STREAM_CHUNK_SIZE
        const windowEnd = windowStart + length

        plaintext.copy(buffer, 0, windowStart, windowEnd)

        return length
    }

    async write(buffer, length, position) {
        if (length === 0 || !this.readCapability || !this.writeCapability) return 0

        const fileSize = await this.#getPlainFileSize()
        if (position > fileSize) throw Error(`Out of bounds write`)

        // Figure out in which chunk the write starts
        const startChunkIndex = this.#ciphertextChunkIndex(position)

        // Read any existing content from chunk and any succeeding chunks.
        // All of this is a no-op if the write is an append.
        const startChunkPosition = this.#chunkPosition(startChunkIndex)
        const startChunkPlainPosition = this.#plaintextLengthFromCiphertextSize(startChunkPosition)

        const readLength = fileSize - startChunkPlainPosition
        const existing = Buffer.alloc(readLength)
        await this.read(existing, existing.byteLength, startChunkPlainPosition)

        const head = existing.subarray(0, position - startChunkPlainPosition)
        const tail = head.byteLength + buffer.byteLength > fileSize ? Buffer.alloc(0) : existing.subarray(head.byteLength + buffer.byteLength)

        // Create a combined buffer of what needs to be encrypted and written.
        const combined = Buffer.concat([head, buffer, tail])

        // Write chunks
        // The file descriptor is currently pointing at any
        let written = 0 // Plaintext bytes written
        let writePosition = startChunkPosition + TOTAL_SIGNATURE_SIZE // Ciphertext position

        while (written < combined.byteLength) {
            const toBeWritten = Math.min(STREAM_CHUNK_SIZE, combined.byteLength - written)
            const plaintext = combined.subarray(written, written + toBeWritten)
            const out = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES + toBeWritten + sodium.crypto_secretbox_MACBYTES)

            // Generate nonce
            const nonce = out.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
            sodium.randombytes_buf(nonce)

            // Encrypt chunk
            const ciphertext = out.subarray(sodium.crypto_secretbox_NONCEBYTES)
            sodium.crypto_secretbox_easy(ciphertext, plaintext, nonce, this.readCapability.key)

            // Write nonce and ciphertext
            await fsFns.write(this.fd, out, 0, out.byteLength, writePosition)

            written += toBeWritten
            writePosition += out.byteLength
        }

        return length
    }
}

module.exports = {
    FileHandle,
    STREAM_CHUNK_SIZE,
    STREAM_CIPHER_CHUNK_SIZE
}
