const fs = require("fs/promises")
const { join } = require("path")
const sodium = require("sodium-native")
const fsFns = require("./fsFns.js")
const { FSError } = require("./util.js")

// The maximum size of a message appended to the stream
// Every chunk, except for the last, in the stream should of this size.
const STREAM_CHUNK_SIZE = 4096

// The maximum size of a chunk after it has been encrypted.
const STREAM_CIPHER_CHUNK_SIZE = STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES

const crypto_secretstream_xchacha20poly1305_COUNTERBYTES = 4
const crypto_secretstream_xchacha20poly1305_INONCEBYTES = 8
const crypto_onetimeauth_poly1305_BYTES = 16

class FileReader {
    /**
     *
     * @param {number} fd
     * @param {Buffer} key
     */
    constructor(fd, key) {
        this.fd = fd
        this.key = key
        this.nonces = []
    }

    get currentChunk() {
        return this._state.i.readUInt32LE() - 1 // The counter starts at 1
    }

    set currentChunk(value) {
        return this._state.i.writeUInt32LE(value + 1) // The counter starts at 1
    }

    async init() {
        this.fileSize = (await fsFns.fstat(this.fd)).size

        const header = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
        await fsFns.read(this.fd, header, 0, header.byteLength, 0)

        this.state = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES)
        sodium.crypto_secretstream_xchacha20poly1305_init_pull(this.state, header, this.key)

        // See definition of state here:
        // https://github.com/jedisct1/libsodium/blob/6d566070b48efd2fa099bbe9822914455150aba9/src/libsodium/include/sodium/crypto_secretstream_xchacha20poly1305.h#L56
        // Note that the counter i and nonce n are concatenated and stored in the same field.
        this._state = {
            k: this.state.subarray(0, sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES),
            i: this.state.subarray(
                // 32, 36
                sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_secretstream_xchacha20poly1305_COUNTERBYTES
            ),
            n: this.state.subarray(
                // 36, 44
                sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_secretstream_xchacha20poly1305_COUNTERBYTES,
                sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES +
                    crypto_secretstream_xchacha20poly1305_COUNTERBYTES +
                    crypto_secretstream_xchacha20poly1305_INONCEBYTES
            )
        }

        // Store the first nonce
        this.nonces.push(Buffer.from(this._state.n))

        // Clear the key as its no longer needed (the derived subkey is stored in state)
        delete this.key
    }

    #ciphertextChunkIndex(plaintextPosition) {
        return Math.floor(plaintextPosition / STREAM_CHUNK_SIZE)
    }

    // Returns the starting position within the ciphertext of a given chunk
    #chunkPosition(index) {
        return sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES + index * STREAM_CIPHER_CHUNK_SIZE
    }

    #plaintextLength(ciphertextBytes) {
        const blockSize = STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
        const blockCount = Math.ceil(ciphertextBytes / blockSize)
        const tagSizes = blockCount * sodium.crypto_secretstream_xchacha20poly1305_ABYTES

        return ciphertextBytes - tagSizes
    }

    async #readChunks(from, to) {
        // assert(from <= to)

        const start = this.#chunkPosition(from)
        // The last chunk of the file may be less than full size.
        const end = Math.min(this.#chunkPosition(to) + STREAM_CIPHER_CHUNK_SIZE, this.fileSize)
        const length = end - start
        const ciphertext = Buffer.alloc(length)

        await fsFns.read(this.fd, ciphertext, 0, length, start)

        return ciphertext
    }

    // Aligns the internal state of the reader so that it is ready to read from the chunk at the given index.
    async #prepareRead(chunkIndex) {
        if (chunkIndex === this.currentChunk) return

        // Check if we have the required nonce.
        await this.#loadNonces(chunkIndex)

        // Set the counter to the requested index
        this.currentChunk = chunkIndex

        // Choose the appropriate nonce
        const nonce = this.nonces[chunkIndex]
        nonce.copy(this._state.n)
    }

    // Ensures that we have all nonces starting from the first up to and including the requested index.
    // For the nonces that we don't have, we will load the required information from the ciphertext
    // and compute them.
    async #loadNonces(requestedIndex) {
        if (this.nonces.length > requestedIndex) return

        const startingIndex = this.nonces.length
        const mac = Buffer.alloc(crypto_onetimeauth_poly1305_BYTES)

        for (let i = startingIndex; i <= requestedIndex; i++) {
            // Load the MAC from the previous chunk.
            // Since the chunk is not the last in the stream, we know for a fact it is full-size.
            const chunkEnd = this.#chunkPosition(i - 1) + STREAM_CIPHER_CHUNK_SIZE
            const macStart = chunkEnd - crypto_onetimeauth_poly1305_BYTES

            await fsFns.read(this.fd, mac, 0, mac.byteLength, macStart)

            const currentNonce = this.nonces[i - 1]
            const nextNonce = Buffer.alloc(8)

            // Compute the next nonce by XOR'ing the current nonce with the first 8 bytes of the MAC.
            for (let n = 0; n < 8; n++) {
                nextNonce[n] = currentNonce[n] ^ mac[n]
            }

            this.nonces.push(nextNonce)
        }
    }

    async read(buffer, length, position) {
        if (length === 0) return 0
        if (!this.state) await this.init()

        // Determine which chunks in the ciphertext stream the read request covers.
        const startChunkIndex = this.#ciphertextChunkIndex(position)
        const endChunkIndex = this.#ciphertextChunkIndex(position + length)

        // Align the reader
        await this.#prepareRead(startChunkIndex)

        // Read ciphertext from disk
        const ciphertext = await this.#readChunks(startChunkIndex, endChunkIndex)

        // Decrypt chunks
        const tag = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_TAGBYTES)
        const plaintextLength = this.#plaintextLength(ciphertext.byteLength)
        const plaintext = Buffer.alloc(plaintextLength)

        const chunks = Math.ceil(plaintextLength / STREAM_CHUNK_SIZE)

        for (let chunk = 0; chunk < chunks; chunk++) {
            const chunkStart = chunk * (STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
            const chunkLength = Math.min(STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES, ciphertext.byteLength - chunkStart)

            const inBuffer = ciphertext.subarray(chunkStart, chunkStart + chunkLength)

            const outStart = chunk * STREAM_CHUNK_SIZE
            const outEnd = outStart + this.#plaintextLength(chunkLength)
            const outBuffer = plaintext.subarray(outStart, outEnd)

            sodium.crypto_secretstream_xchacha20poly1305_pull(this.state, outBuffer, tag, inBuffer, null)

            // Store nonce for later use
            if (this.nonces.length == this.currentChunk) {
                const nonce = Buffer.from(this._state.n)
                this.nonces.push(nonce)
            }
        }

        // Determine what we should return from the plaintext
        // (i.e. we might have to discard some of the head and/or tail of the plaintext to satisfy the request)
        const windowStart = position % STREAM_CHUNK_SIZE
        const windowEnd = windowStart + length

        plaintext.copy(buffer, 0, windowStart, windowEnd)

        return length
    }
}

// function insertInto(source, target, position, length) {
//     const headSlice = source.slice(0, position)
//     const tailSlice = source.slice(position)
//     const truncatedTarget = target.slice(0, length)
//     return Buffer.concat([headSlice, truncatedTarget, tailSlice])
// }

// function encryptBuffer(buffer, key) {
//     const nonce = crypto.makeNonce()
//     const ic = 0
//     const cipher = crypto.streamXOR(buffer, nonce, ic, key)
//     const nonceAndCipher = Buffer.concat([nonce, cipher])
//     return nonceAndCipher
// }

/**
 * Computes the size of a plaintext message based on the size of the ciphertext.
 * @param {number} fileSize
 * @returns size in bytes
 */
function messageSize(fileSize) {
    let size = fileSize

    // Subtract header
    size -= sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES

    // Subtract block headers (17 bytes: MAC + tag)
    const blockSize = STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
    const blockCount = Math.ceil(size / blockSize)
    size -= blockCount * sodium.crypto_secretstream_xchacha20poly1305_ABYTES

    return size
}

class FuseHandlers {
    constructor(baseDir, keyProvider) {
        this.baseDir = baseDir
        this.keyProvider = keyProvider

        // Maps file descriptors to FileReaders
        this.readers = new Map()
    }

    #resolvedPath(path) {
        return join(this.baseDir, path)
    }

    async init() {}

    async access(path, mode) {
        const fullPath = this.#resolvedPath(path)
        return fs.access(fullPath, mode)
    }

    // async statfs(path) {
    //     // TODO: What is the difference between 'statfs' and 'getattr'?
    //     // TODO: Unsure if this is a proper implementation
    //     const res = await fs.stat(join(BASE_DIR, path))
    //     console.log(`Stat ${join(BASE_DIR, path)}`)
    //     console.log(res)
    //     if (!res.isDirectory()) throw new FSError(-1) // TODO: Proper error code
    //     return res
    // }

    async getattr(path) {
        const fullPath = this.#resolvedPath(path)

        try {
            const stat = await fs.stat(fullPath)
            // Overwrite the size of the ciphertext with the size of the plaintext
            stat.size = messageSize(stat.size)
            return stat
        } catch (error) {
            throw new FSError(error.errno)
        }
    }

    // Same as getattr but is called when someone stats a file descriptor
    // async fgetattr(path, fd) {
    //     return fs.fstat(fd)
    // }

    async flush(path, fd) {
        return fsFns.fdatasync(fd)
    }

    async fsync(path, fd, datasync) {
        return fsFns.fsync(fd)
    }

    async fsyncdir(path, fd, datasync) {
        return this.fsync(path, fd, datasync)
    }

    async readdir(path) {
        const fullPath = this.#resolvedPath(path)
        return fs.readdir(fullPath)
    }

    async truncate(path, size) {
        const fullPath = this.#resolvedPath(path)
        fsFns.truncate(fullPath, size)
    }

    async ftruncate(path, fd, size) {
        return fsFns.ftruncate(fd, size)
    }

    // async readlink(path) {
    //     return fs.readlink(join(BASE_DIR, path))
    // }

    // async chown(path, uid, gid) {
    //     return fs.chown(join(BASE_DIR, path), uid, gid)
    // }

    // async chmod(path, mode) {
    //     return fs.chmod(join(BASE_DIR, path), mode)
    // }

    // async mknod(path, mode, deb) { throw FSError.operationNotSupported }
    // async setxattr(path, name, value, position, flags) { throw FSError.operationNotSupported }

    // async getxattr(path, name, position) {
    //     return null
    // }

    // async listxattr(path, name) { throw FSError.operationNotSupported }
    // async removexattr(path, name) { throw FSError.operationNotSupported }

    async open(path, flags) {
        // console.log("[Open]", path, flags)
        const fullPath = this.#resolvedPath(path)
        const file = await fs.open(fullPath, flags)
        const fd = file.fd
        const key = this.keyProvider.getKeyForPath(path)

        this.readers.set(fd, new FileReader(fd, key))

        return fd
    }

    // Called when a file descriptor is being released.Happens when a read/ write is done etc.
    async release(path, fd) {
        this.readers.delete(fd)
    }

    // Same as release but for directories.
    async releasedir(path, fd) {
        return this.release(path, fd)
    }

    // //TODO: Should 'flags' be used for something?
    // async opendir(path, flags) {
    //     const dir = await fs.opendir(path, flags)
    // }

    // async read(path, fd, buffer, length, position) {
    //     // const fullPath = join(FSP_DIR, path)
    //     // const stat = await fs.stat(fullPath)

    //     // TODO: This should instead be handled by the decryption failing
    //     // if (position >= stat.size - crypto.NONCE_LENGTH) throw new FSError(-1) // read-error occured. TODO: use proper error code

    //     const key = this.keyProvider.getKeyForPath(path)
    //     const nonce = await readNonce(fd)
    //     const cipher = await readCipher(fd, position, length)
    //     const plain = crypto.decryptSlice2(cipher, nonce, key, position, length)

    //     // TODO: Avoid copy
    //     plain.copy(buffer) // copy 'plain' into buffer

    //     return plain.byteLength
    // }

    async read(path, fd, buffer, length, position) {
        // console.log("[Read]", fd)

        const reader = this.readers.get(fd)
        if (!reader) {
            throw new Error("Read from closed file descriptor")
        }

        const bytesRead = await reader.read(buffer, length, position)

        return bytesRead
    }

    // Encrypts before writing to disk. Each write-call re-encrypts the file at 'path' using a fresh nonce.
    // Assumes the file at 'path' already exists
    // async write(path, fd, buffer, length, position) {
    //     const fullPath = join(FSP_DIR, path)
    //     const key = keyProvider.getKeyForPath(path)
    //     // const stat = await this.getattr(path)
    //     const stat = await fs.stat(path) // TODO: Use size-corrected stat instead

    //     if (position > stat.size) {
    //         // Attempt to write outside of file
    //         throw new FSError(-1) // TODO: Proper error code
    //     }

    //     if (stat.size === 0) {
    //         // nothing to decrypt before encrypting the write
    //         const cipher = encryptBuffer(buffer, key)
    //         const res = await fsFns.write(fd, cipher)
    //         return length
    //     } else {
    //         // We need to decrypt the existing content of file at 'path',
    //         // add the new write and re-encrypt it all under a new nonce

    //         // Read all of the existing content into 'readBuffer'
    //         const file = await fs.open(fullPath, "r")
    //         const readBuffer = Buffer.alloc(stat.size - crypto.NONCE_LENGTH)
    //         const readLength = await this.read(path, file.fd, readBuffer, readBuffer.length, 0)

    //         await file.close()

    //         if (readLength !== readBuffer.length) throw new FSError(-1) // read-error occured. TODO: use proper error code
    //         if (position > readBuffer.byteLength) throw new FSError(-1) // We try to write 'buffer' into a 'position' in 'readBuffer' that does not exist. TODO: Unsure how to handle this case yet.

    //         // insert 'buffer' into the 'readBuffer' at position
    //         const updatedReadBuffer = insertInto(readBuffer, buffer, position, length)
    //         const cipher = encryptBuffer(updatedReadBuffer, key)
    //         // await fs.writeFile(fullPath, cipher)
    //         await fsFns.write(fd, cipher, 0, cipher.byteLength, 0)

    //         return length
    //     }
    // }

    async write(path, fd, buffer, length, position) {
        const res = await fsFns.write(fd, buffer, position, length)
        return res.bytesWritten
    }

    async create(path, mode) {
        // 'wx+': Open file for reading and writing. Creates file but fails if the path exists.
        const fd = await fs.open(this.#resolvedPath(path), "wx+", mode)
        await fd.close()
    }

    async utimens(path, atime, mtime) {
        return fs.utimes(this.#resolvedPath(path), atime, mtime)
    }

    async unlink(path) {
        await fs.unlink(this.#resolvedPath(path))
    }

    async rename(src, dest) {
        await fs.rename(this.#resolvedPath(src), this.#resolvedPath(dest))
    }

    // async link(src, dest) {
    //     return fs.link(join(BASE_DIR, src), join(BASE_DIR, dest))
    // }

    // async symlink(src, dest) {
    //     return fs.symlink(join(BASE_DIR, dest), join(BASE_DIR, src))
    // }

    async mkdir(path, mode) {
        return fs.mkdir(this.#resolvedPath(path), { recursive: false, mode: mode })
    }

    async rmdir(path) {
        return fs.rmdir(this.#resolvedPath(path))
    }
}

module.exports = {
    FuseHandlers,
    STREAM_CHUNK_SIZE
}
