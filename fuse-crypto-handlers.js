const fs = require('fs')
const fsP = require('fs/promises')
const crypto = require('./crypto')
const util = require('util')
const { isAsyncFunction } = require('util/types')
class FSError extends Error {
    constructor(code) {
        super()
        this.code = code
    }
}

function callbackify(fn) {
    const SUCCESS = 0
    var fnLength = fn.length
    return function () {
        var args = [].slice.call(arguments)
        var ctx = this
        if (args.length === fnLength + 1 &&
            typeof args[fnLength] === 'function') {
            // callback mode
            var cb = args.pop()
            fn.apply(this, args)
                .then(function (val) {
                    console.log("Calling CB with res: ", val)
                    cb.call(ctx, SUCCESS, val)
                })
                .catch(function (err) {
                    let code = -1
                    console.log("Calling CB with err: ", err)
                    if (err instanceof FSError) {
                        code = err.code
                    }

                    cb.call(ctx, code)
                })
            return
        }
        // promise mode
        return fn.apply(ctx, arguments)
    }
}

class KeyProvider {
    constructor() {
        this._keymap = new Map()
    }

    getKeyForPath(path) {
        if (!this._keymap.has(path)) this._keymap.set(path, crypto.makeSymmetricKey()) // create new key for path if existing key doesnt exist
        return this._keymap.get(path)
    }
}

function insertInto(source, target, position, length) {
    const headSlice = source.slice(0, position)
    const tailSlice = source.slice(position)
    const truncatedTarget = target.slice(0, length)
    return Buffer.concat([headSlice, truncatedTarget, tailSlice])
}

function readNonceAtPath(path, cb) {
    // Read out the nonce of the file.
    const nonceReadStream = fs.createReadStream(path, { start: 0, end: crypto.NONCE_LENGTH })

    // Wait for the stream to be readable, otherwise '.read' is invalid.
    nonceReadStream.on('readable', () => {
        const nonce = nonceReadStream.read(crypto.NONCE_LENGTH)
        nonceReadStream.close() // close stream to ensure on('readable') is not called multiple times
        if (!nonce || nonce.length !== crypto.NONCE_LENGTH) cb(null) // An error occured.
        else cb(nonce)
    })
}

const keyProvider = new KeyProvider()

const handlers = {
    init(cb) { },

    async access(path, mode) {
        return fsP.access(path, mode)
    },

    async statfs(path) {
        // TODO: What is the difference between 'statfs' and 'getattr'?
        // TODO: Unsure if this is a proper implementation
        const res = await fsP.stat(path)
        if (!res.isDirectory()) throw new FSError(-1) // TODO: Proper error code
        return res
    },

    async getattr(path) {
        return fsP.stat(path)
    },

    async fgetattr(path, fd) {
        return fsP.fstat(fd)
    },

    //TODO: Performance optimisation. Write to in-mem buffer instead of directly to disk. Then use 'flush' to store the in-mem buffer on disk.
    async flush(path, fd) { },

    async fsync(path, fd, datasync) {
        return fsP.fsync(fd)
    },

    //TODO: Different implementation of 'fsync' and fsyncdir'?
    async fsyncdir(path, fd, datasync) { },

    async readdir(path) {
        return fsP.readdir(path)
    },

    async truncate(path, size) {
        return fsP.truncate(path, size)
    },

    async ftruncate(path, fd, size) {
        return fsP.ftruncate(fd, size)
    },

    async readLink(path) {
        return fsP.readlink(path)
    },

    async chown(path, uid, gid) {
        return fsP.chown(path, uid, gid)
    },

    async chmod(path, mode) {
        return fsP.chmod(path, mode)
    },

    async mknod(path, mode, deb) { },
    async setxattr(path, name, value, position, flags) { },
    async getxattr(path, name, position) { },
    async listxattr(path, name) { },
    async removexattr(path, name) { },

    async open(path, flags) {
        return fsP.open(path, flags)
    },

    //TODO: Should 'flags' be used for something?
    async opendir(path, flags) {
        return fsP.opendir(path)
    },

    // write content into 'buffer' to be read by the caller
    // TODO: Optimization: Instead of creating the readstream at each call, only open the file once and close when the end of the file is reached
    // TODO: Does the readstream close itself when the end its end is reached?
    read: function (path, fd, buffer, length, position, cb) {
        fs.stat(path, (err, stats) => {
            if (err) return cb(0) // Error occured. Mark file as read //TODO: Use proper error code?

            // Check if caller tries to read from a position after the file content.
            // Note that 'stats.size' includes the prepended buffer. Must be subtracted.
            if (position >= stats.size - crypto.NONCE_LENGTH) return cb(0) // Reached end of file. Mark 0 bytes written to 'buffer'

            readNonceAtPath(path, (nonce) => {
                if (!nonce) return cb(0) // An error occured. Mark 0 bytes written to 'buffer'

                // Create a readstream only for the relevant slice of 'cipher'.
                // The readstream must start reading from the beginning of the first block of the cipher for the decryption to be valid.
                const firstBlockOffset = position % crypto.STREAM_BLOCK_SIZE
                const opts = {                                                          // Offset the stream with 'NONCE_LENGTH' to skip the prepended nonce.
                    start: crypto.NONCE_LENGTH + position - firstBlockOffset,           // Subtract the offset of the first-block to make the readstream start at beginning of first block.
                    end: crypto.NONCE_LENGTH + position + firstBlockOffset + length   // Add the offset of the first block to counter the subtraction in 'start'. Otherwise the stream-length would be too short.
                }
                const cipherReadStream = fs.createReadStream(path, opts)

                // Wait for the stream to be readable, otherwise '.read' is invalid.
                cipherReadStream.on('readable', () => {
                    // 'content' may be shorter than 'length' when near the end of the stream.
                    // The stream returns 'null' when the end is reached
                    const cipher = cipherReadStream.read() // Read the stream
                    cipherReadStream.close() // close stream to ensure on('readable') is not called multiple times
                    if (!cipher || cipher.length === 0) return cb(0) // end of file reached

                    // Decrypt the file-content
                    const key = keyProvider.getKeyForPath(path)
                    const plain = crypto.decryptSlice2(cipher, nonce, key, position, length)

                    plain.copy(buffer) // copy 'plain' into buffer
                    cb(plain.length) // return number of bytes written to 'buffer'
                })
            })
        })
    },

    readP: async function (path, fd, buffer, length, position) {
        return new Promise((resolve, reject) => {
            this.read(path, fd, buffer, length, position, (err) => {
                console.log("Read res", err)
                if (err && err < 0) {
                    reject(err)
                    return
                }

                const readLength = err

                resolve(readLength)

            })
        })
    },

    // Encrypts before writing to disk. Each write-call re-encrypts the file at 'path' using a fresh nonce.
    // Assumes the file at 'path' already exists
    async write(path, fd, buffer, length, position) {
        const key = keyProvider.getKeyForPath(path)

        const stat = await fsP.stat(path)

        if (stat.size === 0) {
            // nothing to decrypt
            const nonce = crypto.makeNonce()
            const ic = 0
            const cipher = crypto.streamXOR(buffer, nonce, ic, key)
            const nonceAndCipher = Buffer.concat([nonce, cipher])

            await fsP.writeFile(path, nonceAndCipher)
            return cipher.length
        } else {
            // We need to decrypt the existing content of file at 'path',
            // add the new write and re-encrypt it all under a new nonce

            // Read all of the existing content into 'readBuffer'
            const readBuffer = Buffer.alloc(stat.size - crypto.NONCE_LENGTH)
            const readLength = await this.readP(path, fd, readBuffer, readBuffer.length, 0)

            if (readLength !== readBuffer.length) throw new FSError(-1) // read-error occured. TODO: use proper error code
            if (position > readBuffer.length) throw new FSError(-1) // We try to write 'buffer' into a 'position' in 'readBuffer' that does not exist. TODO: Unsure how to handle this case yet.
            // insert 'buffer' into the 'readBuffer' at position
            const updatedReadBuffer = insertInto(readBuffer, buffer, position, length)

            // Encrypt using a fresh nonce
            const nonce = crypto.makeNonce()
            const ic = 0 // We start from 0 since the entire buffer is re-encrypted
            const cipher = crypto.streamXOR(updatedReadBuffer, nonce, ic, key)

            // prepend nonce
            const nonceAndCipher = Buffer.concat([nonce, cipher])

            // write to 'path'
            await fsP.writeFile(path, nonceAndCipher)
            return length
        }
    },

    release(path, fd, cb) {
        fs.close(fd, (err) => {
            if (err) cb(1)
            else cb(0)
        })
    },

    releasedir(path, fd, cb) {
        this.release(path, fd, cb) //TODO: Is this okay? If not, what are the differences?
    },

    create(path, mode) {
        // 'wx+': Open file for reading and writing. Creates file but fails if the path exists.
        return fsP.open(path, "wx+", mode)
    },

    utimens(path, atime, mtime, cb) { },
    unlink(path, cb) { },
    rename(src, dest, cb) { },

    async link(src, dest) {
        return fsP.link(src, dest)
    },

    async symlink(src, dest) {
        return fsP.symlink(dest, src)
    },

    async mkdir(path, mode) {
        return fsP.mkdir(path, { recursive: false, mode: mode })
    },

    async rmdir(path) {
        return fsP.rmdir(path)
    }
}

// Callbackify async handlers
for (let key of Object.keys(handlers)) {
    const fn = handlers[key]
    if (isAsyncFunction(fn)) {
        handlers[key] = callbackify(fn)
    }
}

module.exports = handlers