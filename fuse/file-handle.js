const { createReadStream } = require("fs")
const sodium = require("sodium-native")
const fsFns = require("../utilities/fsFns.js")
const { signDetached, Hasher } = require("../utilities/crypto")
const {
    STREAM_CHUNK_SIZE,
    STREAM_CIPHER_CHUNK_SIZE,
    MAC_LENGTH,
    NONCE_LENGTH,
    SIGNATURE_SIZE,
    CAPABILITY_TYPE_READ,
    CAPABILITY_TYPE_WRITE,
    CAPABILITY_TYPE_VERIFY
} = require("../constants")
const Fuse = require("fuse-native")
const FSError = require("./fs-error.js")

class FileHandle {
    /**
     * @param {number} fd
     * @param {Buffer} capabilities
     */
    constructor(fd, capabilities) {
        this.fd = fd

        this.readCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_READ)
        this.writeCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_WRITE)
        this.verifyCapability = capabilities.find(cap => cap.type === CAPABILITY_TYPE_VERIFY)

        this.hasher = new Hasher()
        this.needsRehash = true
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
        const metadataSize = MAC_LENGTH + NONCE_LENGTH

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
        if (length === 0) return 0
        if (!this.readCapability) throw new FSError(Fuse.EACCES)

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

            const nonce = inBuffer.subarray(0, NONCE_LENGTH)
            const encrypted = inBuffer.subarray(NONCE_LENGTH)

            const outStart = chunk * STREAM_CHUNK_SIZE
            const outEnd = outStart + this.#plaintextLength(chunkLength)
            const outBuffer = plaintext.subarray(outStart, outEnd)
            const res = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(outBuffer, null, encrypted, null, nonce, this.readCapability.key)
            if (!res) throw new FSError(Fuse.EIO)
        }

        // Determine what we should return from the plaintext
        // (i.e. we might have to discard some of the head and/or tail of the plaintext to satisfy the request)
        const windowStart = position % STREAM_CHUNK_SIZE
        const windowEnd = windowStart + length

        plaintext.copy(buffer, 0, windowStart, windowEnd)

        return length
    }

    async write(buffer, length, position) {
        if (length === 0) return 0
        if (!this.readCapability || !this.writeCapability) throw new FSError(Fuse.EACCES)

        const fileSize = await this.#getPlaintextLength()
        if (position > fileSize) throw new FSError(Fuse.EINVAL)

        let head = Buffer.alloc(0)
        let tail = Buffer.alloc(0)

        // Prepare head
        // Figure out in which chunk the write starts
        const startChunkIndex = this.#ciphertextChunkIndex(position)
        const startChunkPosition = this.#chunkPosition(startChunkIndex)
        const startChunkPlainPosition = this.#plaintextLength(startChunkPosition)

        if (startChunkPlainPosition < position) {
            // The write is offset in the start chunk
            head = Buffer.alloc(position - startChunkPlainPosition)
            await this.read(head, head.byteLength, startChunkPlainPosition)
        }

        // Prepare tail
        const endPosition = position + length

        // If the write ends outside the current bounds of the file, there is no tail.
        if (endPosition < fileSize) {
            const nextChunkIndex = this.#ciphertextChunkIndex(endPosition) + 1
            const nextChunkPosition = this.#chunkPosition(nextChunkIndex)
            const nextChunkPlainPosition = this.#plaintextLength(nextChunkPosition)

            // The tail starts where the write ends and ends at boundary of the chunk, in which the write ends.
            const tailStart = endPosition
            const tailEnd = Math.min(fileSize, nextChunkPlainPosition)

            tail = Buffer.alloc(tailEnd - tailStart)
            await this.read(tail, tail.byteLength, endPosition)
        }

        // Create a combined buffer of what needs to be encrypted and written.
        const combined = Buffer.concat([head, buffer, tail])

        // Write chunks
        // The file descriptor is currently pointing at any
        let written = 0 // Plaintext bytes written
        let writePosition = startChunkPosition + SIGNATURE_SIZE // Ciphertext position

        const isAppending = position == fileSize

        while (written < combined.byteLength) {
            const toBeWritten = Math.min(STREAM_CHUNK_SIZE, combined.byteLength - written)
            const plaintext = combined.subarray(written, written + toBeWritten)
            const out = Buffer.alloc(NONCE_LENGTH + toBeWritten + MAC_LENGTH)

            // Generate nonce
            const nonce = out.subarray(0, NONCE_LENGTH)
            sodium.randombytes_buf(nonce)

            // Encrypt chunk
            const ciphertext = out.subarray(NONCE_LENGTH)
            sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, plaintext, null, null, nonce, this.readCapability.key)

            // Update hasher state
            if (isAppending) {
                this.hasher.update(out)
                this.needsRehash = false
            } else {
                this.needsRehash = true
            }

            // Write nonce and ciphertext
            await fsFns.write(this.fd, out, 0, out.byteLength, writePosition)

            written += toBeWritten
            writePosition += out.byteLength
        }

        return length
    }

    async createSignature() {
        if (this.needsRehash) {
            this.hasher = new Hasher()

            // Compute hash of entire file except the signature.
            const stream = createReadStream(null, {
                fd: this.fd,
                start: SIGNATURE_SIZE,
                autoClose: false
            })

            for await (const chunk of stream) {
                this.hasher.update(chunk)
            }

            this.needsRehash = false
        }

        const hash = this.hasher.final()

        const signature = signDetached(hash, this.writeCapability.key)
        await fsFns.write(this.fd, signature, 0, signature.byteLength, 0)
    }
}

module.exports = FileHandle
