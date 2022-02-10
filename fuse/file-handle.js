const sodium = require("sodium-native")
const fsFns = require("../fsFns.js")
const { signDetached } = require("../crypto")
const { createHash } = require("crypto")
const {
    STREAM_CHUNK_SIZE,
    STREAM_CIPHER_CHUNK_SIZE,
    SIGNATURE_SIZE,
    CAPABILITY_TYPE_READ,
    CAPABILITY_TYPE_WRITE,
    CAPABILITY_TYPE_VERIFY
} = require("../constants")

class FileHandle {
    /**
     * TODO: Fix params documentation
     * @param {number} fd
     * @param {Buffer} key
     */
    constructor({ fd, path, capabilities }) {
        this.fd = fd
        this.path = path

        this.readCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_READ) //TODO: refactor to not depend on TYPE_READ
        this.writeCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_WRITE)
        this.verifyCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_VERIFY)

        this.hash = createHash("sha256") // a rolling hash
        this.shouldHashExistingMACs = true
    }

    /**
     * Returns the length of the file on disk. This includes signature and ciphertext.
     */
    async #getFileLength() {
        const stat = await fsFns.fstat(this.fd)
        return stat.size
    }

    /**
     * Returns the length of the plaintext (i.e. the file after it has been decrypted).
     */
    async #getPlaintextLength() {
        const fileLength = await this.#getFileLength()
        const ciphertextLength = fileLength - SIGNATURE_SIZE
        return this.#plaintextLength(ciphertextLength)
    }

    #plaintextLength(ciphertextLength) {
        // Each chunk has metadata in the form of an authentication tag (MAC) and a nonce.
        const metadataSize = sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES

        // Compute how many chunks are in the encrypted file.
        const chunkCount = Math.ceil(ciphertextLength / STREAM_CIPHER_CHUNK_SIZE)
        
        return ciphertextLength - chunkCount * metadataSize
    }

    // Returns the index of the chunk that a position in the plaintext corresponds to.
    #ciphertextChunkIndex(plaintextPosition) {
        return Math.floor(plaintextPosition / STREAM_CHUNK_SIZE)
    }

    // Returns the starting position within the ciphertext of a given chunk
    #chunkPosition(index) {
        return index * STREAM_CIPHER_CHUNK_SIZE
    }

    async #readChunks(from, to) {
        //TODO: When reading from start to finish, we load two chunks every time, but J thinks we only need to load one. Check if this is the case
        const fileSize = await this.#getFileLength()

        const start = this.#chunkPosition(from) + SIGNATURE_SIZE
        // The last chunk of the file may be less than full size.
        const end = Math.min(this.#chunkPosition(to) + STREAM_CIPHER_CHUNK_SIZE + SIGNATURE_SIZE, fileSize)
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
        const plaintextLength = this.#plaintextLength(ciphertext.byteLength)
        const plaintext = Buffer.alloc(plaintextLength)

        const chunks = Math.ceil(plaintextLength / STREAM_CHUNK_SIZE)

        for (let chunk = 0; chunk < chunks; chunk++) {
            const chunkStart = chunk * STREAM_CIPHER_CHUNK_SIZE
            const chunkLength = Math.min(STREAM_CIPHER_CHUNK_SIZE, ciphertext.byteLength - chunkStart)

            const inBuffer = ciphertext.subarray(chunkStart, chunkStart + chunkLength)

            const nonce = inBuffer.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
            const encrypted = inBuffer.subarray(sodium.crypto_secretbox_NONCEBYTES)

            const outStart = chunk * STREAM_CHUNK_SIZE
            const outEnd = outStart + this.#plaintextLength(chunkLength)
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

        const fileSize = await this.#getPlaintextLength()
        if (position > fileSize) throw Error(`Out of bounds write`)

        // Figure out in which chunk the write starts
        const startChunkIndex = this.#ciphertextChunkIndex(position)

        // Read any existing content from chunk and any succeeding chunks.
        // All of this is a no-op if the write is an append.
        const startChunkPosition = this.#chunkPosition(startChunkIndex)
        const startChunkPlainPosition = this.#plaintextLength(startChunkPosition)

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
        let writePosition = startChunkPosition + SIGNATURE_SIZE // Ciphertext position

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

            // update hash used for signature
            this.hash.update(out)
            // Write nonce and ciphertext
            await fsFns.write(this.fd, out, 0, out.byteLength, writePosition)

            written += toBeWritten
            writePosition += out.byteLength
        }

        return length
    }

    async createSignature() {
        if (this.shouldHashExistingMACs) {
            this.shouldHashExistingMACs = false

            // Compute hash of entire file except the signature in the
            // same block size as they were written.
            // const fd = await fsFns.open(this.path, "r") // we make a new fd to ensure it is allowed to read ("r")
            const fileLength = await this.#getFileLength()
            const ciphertextLength = fileLength - SIGNATURE_SIZE
            const chunkCount = Math.ceil(ciphertextLength / STREAM_CIPHER_CHUNK_SIZE)
            const offset = SIGNATURE_SIZE

            let read = 0
            for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
                const start = chunkIndex * STREAM_CIPHER_CHUNK_SIZE + offset
                const chunkSize = Math.min(STREAM_CIPHER_CHUNK_SIZE, ciphertextLength - read)
                const chunk = Buffer.alloc(chunkSize)
                await fsFns.read(this.fd, chunk, 0, chunk.byteLength, start)
                this.hash.update(chunk)
                read += chunkSize
            }
        }

        const hash = Buffer.from(this.hash.copy().digest("hex"), "hex") // We digest a copy to continue rolling the hash for the next writes
        const signature = signDetached(hash, this.writeCapability.key)
        await fsFns.write(this.fd, signature, 0, signature.byteLength, 0)
    }
}

module.exports = {
    FileHandle,
    STREAM_CHUNK_SIZE,
    STREAM_CIPHER_CHUNK_SIZE,
    SIGNATURE_SIZE
}
