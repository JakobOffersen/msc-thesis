const fs = require("fs/promises")
const fsS = require("fs")
const crypto = require("./crypto")
const { FSError } = require("./util.js")
const { join, resolve } = require("path")
const { promisify } = require("util")

const FSP_DIR = resolve("./fsp")

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

async function readNonce(fd) {
    const nonce = Buffer.alloc(crypto.NONCE_LENGTH)
    await fsFns.read(fd, nonce, 0, crypto.NONCE_LENGTH, 0) // fill 'nonce' with the first 'NONCE_LENGTH' bytes of 'file
    return nonce
}

async function readCipher(fd, position, length) {
    const { start, windowLength } = computeReadWindow(position, length)
    const cipher = Buffer.alloc(windowLength)
    await fsFns.read(fd, cipher, 0, windowLength, start)
    return cipher
}

function encryptBuffer(buffer, key) {
    const nonce = crypto.makeNonce()
    const ic = 0
    const cipher = crypto.streamXOR(buffer, nonce, ic, key)
    const nonceAndCipher = Buffer.concat([nonce, cipher])
    return nonceAndCipher
}

const keyProvider = new KeyProvider()

/*
The fs/promises module in Node.js provides functions that that take a FileHandle object,
whereas the functions in the fs module take a file descriptor (number).
Since most handlers are called with a file descriptor that we need to operate on, we have to
use the fs module and provide promise support ourselves.
*/
const fsFns = {
    read: promisify(fsS.read).bind(fsS),
    write: promisify(fsS.write).bind(fsS),
    truncate: promisify(fsS.truncate).bind(fsS),
    ftruncate: promisify(fsS.ftruncate).bind(fsS),
    fdatasync: promisify(fsS.fdatasync).bind(fsS),
    fsync: promisify(fsS.fsync).bind(fsS),
    close: promisify(fsS.close).bind(fsS),
}

const handlers = {
    async init() { },

    async access(path, mode) {
        const fullPath = join(FSP_DIR, path)
        return fs.access(fullPath, mode)
    },

    // async statfs(path) {
    //     // TODO: What is the difference between 'statfs' and 'getattr'?
    //     // TODO: Unsure if this is a proper implementation
    //     const res = await fs.stat(join(BASE_DIR, path))
    //     console.log(`Stat ${join(BASE_DIR, path)}`)
    //     console.log(res)
    //     if (!res.isDirectory()) throw new FSError(-1) // TODO: Proper error code
    //     return res
    // },

    async getattr(path) {
        const fullPath = join(FSP_DIR, path)

        try {
            const stat = await fs.stat(fullPath)
            return stat
        } catch (error) {
            throw new FSError(error.errno)
        }
    },

    // Same as getattr but is called when someone stats a file descriptor
    // async fgetattr(path, fd) {
    //     return fs.fstat(fd)
    // },

    // //TODO: Performance optimisation. Write to in-mem buffer instead of directly to disk. Then use 'flush' to store the in-mem buffer on disk.
    async flush(path, fd) {
        return fsFns.fdatasync(fd)
    },

    async fsync(path, fd, datasync) {
        return fsFns.fsync(fd)
    },

    async fsyncdir(path, fd, datasync) {
        return this.fsync(path, fd, datasync)
    },

    async readdir(path) {
        const fullPath = join(FSP_DIR, path)
        return fs.readdir(fullPath)
    },

    async truncate(path, size) {
        const fullPath = join(FSP_DIR, path)
        fsFns.truncate(fullPath, size)
    },

    async ftruncate(path, fd, size) {
        return fsFns.ftruncate(fd, size)
    },

    // async readlink(path) {
    //     return fs.readlink(join(BASE_DIR, path))
    // },

    // async chown(path, uid, gid) {
    //     return fs.chown(join(BASE_DIR, path), uid, gid)
    // },

    // async chmod(path, mode) {
    //     return fs.chmod(join(BASE_DIR, path), mode)
    // },

    // async mknod(path, mode, deb) { throw FSError.operationNotSupported },
    // async setxattr(path, name, value, position, flags) { throw FSError.operationNotSupported },
    // async getxattr(path, name, position) { throw FSError.operationNotSupported },
    // async listxattr(path, name) { throw FSError.operationNotSupported },
    // async removexattr(path, name) { throw FSError.operationNotSupported },

    async open(path, flags) {
        const fullPath = join(FSP_DIR, path)
        const file = await fs.open(fullPath, flags)
        return file.fd
    },

    // //TODO: Should 'flags' be used for something?
    // async opendir(path, flags) {
    //     const dir = await fs.opendir(path, flags)
    // },

    async read(path, fd, buffer, length, position) {
        const fullPath = join(FSP_DIR, path)
        const stat = await fs.stat(fullPath)

        if (position >= stat.size - crypto.NONCE_LENGTH) throw new FSError(-1) // read-error occured. TODO: use proper error code

        const key = keyProvider.getKeyForPath(path)
        const nonce = await readNonce(fd)
        const cipher = await readCipher(fd, position, length)
        const plain = crypto.decryptSlice2(cipher, nonce, key, position, length)

        // TODO: Avoid copy
        plain.copy(buffer) // copy 'plain' into buffer

        return plain.length
    },

    // async read(path, fd, buf, len, pos) {
    //     const res = await fsFns.read(fd, buf, 0, len, pos)
    //     return res.bytesRead
    // },

    // Encrypts before writing to disk. Each write-call re-encrypts the file at 'path' using a fresh nonce.
    // Assumes the file at 'path' already exists
    async write(path, fd, buffer, length, position) {
        const fullPath = join(FSP_DIR, path)
        const key = keyProvider.getKeyForPath(path)
        const stat = await fs.stat(fullPath)

        if (stat.size === 0) {
            // nothing to decrypt before encrypting the write
            const cipher = encryptBuffer(buffer, key)
            const res = await fsFns.write(fd, cipher, 0, length, position)
            return cipher.length - crypto.NONCE_LENGTH // Mark the the cipher was successfully written. Subtract nonce-bytes to hide the prepended nonce
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
            const cipher = encryptBuffer(updatedReadBuffer, key)
            // await fs.writeFile(fullPath, cipher)
            await fsFns.write(fd, cipher, 0, length, position)

            return length
        }
    },

    // async write(path, fd, buffer, length, position) {
    //     const res = await fsFns.write(fd, buffer, position, length)
    //     return res.bytesWritten
    // },

    // Called when a file descriptor is being released.Happens when a read/ write is done etc.
    async release(path, fd) {
        return
    },

    // Same as release but for directories.
    async releasedir(path, fd) {
        return this.release(path, fd)
    },

    async create(path, mode) {
        // 'wx+': Open file for reading and writing. Creates file but fails if the path exists.
        const fd = await fs.open(join(FSP_DIR, path), "wx+", mode)
        await fd.close()
    },

    async utimens(path, atime, mtime) {
        return fs.utimes(join(FSP_DIR, path), atime, mtime)
    },

    async unlink(path) {
        await fs.unlink(join(FSP_DIR, path))
    },

    async rename(src, dest) {
        await fs.rename(join(FSP_DIR, src), join(FSP_DIR, dest))
    },

    // async link(src, dest) {
    //     return fs.link(join(BASE_DIR, src), join(BASE_DIR, dest))
    // },

    // async symlink(src, dest) {
    //     return fs.symlink(join(BASE_DIR, dest), join(BASE_DIR, src))
    // },

    async mkdir(path, mode) {
        return fs.mkdir(join(FSP_DIR, path), { recursive: false, mode: mode })
    },

    async rmdir(path) {
        return fs.rmdir(join(FSP_DIR, path))
    }

}

module.exports = handlers