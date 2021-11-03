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
                    cb.call(ctx, SUCCESS, val)
                })
                .catch(function (err) {
                    let code = -1
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

function computeReadWindow(position, length) {
    const firstBlockOffset = position % crypto.STREAM_BLOCK_SIZE
    return {                                                        // Offset the stream with 'NONCE_LENGTH' to skip the prepended nonce.
        start: crypto.NONCE_LENGTH + position - firstBlockOffset,   // Subtract the offset of the first-block to make the readstream start at beginning of first block.
        windowLength: firstBlockOffset + length
    }
}

async function readNonceInFile(file) {
    const nonce = Buffer.alloc(crypto.NONCE_LENGTH)
    await file.read(nonce, 0, crypto.NONCE_LENGTH, 0) // fill 'nonce' with the first 'NONCE_LENGTH' bytes of 'file
    return nonce
}

async function readCipherInFile(file, position, length) {
    const { start, windowLength } = computeReadWindow(position, length)
    const cipher = Buffer.alloc(windowLength)
    await file.read(cipher, 0, windowLength, start)
    return cipher
}

const keyProvider = new KeyProvider()

const handlers = {
    async init() { },

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
    async read(path, fd, buffer, length, position) {
        const stat = await fsP.stat(path)
        const file = await fsP.open(path, "r")
        if (position >= stat.size - crypto.NONCE_LENGTH) throw new FSError(-1) // read-error occured. TODO: use proper error code

        const key = keyProvider.getKeyForPath(path)
        const nonce = await readNonceInFile(file)
        const cipher = await readCipherInFile(file, position, length)
        const plain = crypto.decryptSlice2(cipher, nonce, key, position, length)
        plain.copy(buffer) // copy 'plain' into buffer
        await file.close()
        return plain.length
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
            const readLength = await this.read(path, fd, readBuffer, readBuffer.length, 0)

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

    async create(path, mode) {
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