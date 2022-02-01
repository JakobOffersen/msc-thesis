const fs = require("fs/promises")
const { join, basename } = require("path")
const sodium = require("sodium-native")
const fsFns = require("../fsFns.js")
const Fuse = require("fuse-native")
const { FileHandle, STREAM_CHUNK_SIZE, STREAM_CIPHER_CHUNK_SIZE } = require("./file-handle")
const { hasSignature, appendSignature, TOTAL_SIGNATURE_SIZE, removeSignature, prependSignature } = require("./file-signer")
const HandleHolder = require("./handle-holder")

class FSError extends Error {
    constructor(code) {
        super()
        this.code = code
    }
}
function ignored(path) {
    const ignore = basename(path).startsWith(".")
    //if (ignore) console.log(`ignored ${path}`)
    return ignore
}
/**
 * Computes the size of a plaintext message based on the size of the ciphertext.
 * @param {number} fileSize
 * @returns size in bytes
 */
function messageSize(ciphertextBytes) {
    ciphertextBytes = ciphertextBytes - TOTAL_SIGNATURE_SIZE

    const blockCount = Math.ceil(ciphertextBytes / STREAM_CIPHER_CHUNK_SIZE)
    const tagSizes = blockCount * (sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES)

    return Math.max(ciphertextBytes - tagSizes, 0) // some resource forks are not signed, since they are not created through the mount-point. All files should be of least size 0.
}

class FuseHandlers {
    constructor(baseDir, keyRing) {
        this.baseDir = baseDir
        this.keyRing = keyRing

        // Maps file descriptors to FileHandles
        this.handles = new HandleHolder()
    }

    #resolvedPath(path) {
        return join(this.baseDir, path)
    }

    async init() {}

    async access(path, mode) {
        const fullPath = this.#resolvedPath(path)
        return fs.access(fullPath, mode)
    }

    async statfs(path) {
        // TODO: The fs module in Node doesn't support the statfs operation.
        // const res = await statvfs(path)
        // console.log("Statfs: ", path)
        // console.log(res)
        // return res
        return {
            bsize: 4096,
            frsize: 4096,
            blocks: 2621440,
            bfree: 2525080,
            bavail: 2525080,
            files: 292304,
            ffree: 289126,
            favail: 289126,
            fsid: 140509193,
            flag: 4,
            namemax: 255
        }
    }

    async getattr(path) {
        if (ignored(path)) throw new FSError(Fuse.ENOENT)

        const fullPath = this.#resolvedPath(path)
        const stat = await fs.stat(fullPath)
        // Overwrite the size of the ciphertext with the size of the plaintext
        if (stat.isFile()) stat.size = messageSize(stat.size)
        return stat
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
        fsFns.truncate(fullPath, size + TOTAL_SIGNATURE_SIZE)
    }

    async ftruncate(path, fd, size) {
        return fsFns.ftruncate(fd, size + TOTAL_SIGNATURE_SIZE)
    }

    // async readlink(path) {
    //     return fs.readlink(join(BASE_DIR, path))
    // }

    async chown(path, uid, gid) {
        const fullPath = this.#resolvedPath(path)
        return fs.chown(fullPath, uid, gid)
    }

    async chmod(path, mode) {
        const fullPath = this.#resolvedPath(path)
        return fs.chmod(fullPath, mode)
    }

    // FUSE calls create instead
    // async mknod(path, mode, deb) { throw FSError.operationNotSupported }

    // async setxattr(path, name, value, position, flags) {
    //     const fullPath = this.#resolvedPath(path)
    //     await xattr.set(fullPath, name, value)
    // }

    // async getxattr(path, name, position) {
    //     // return Buffer.alloc(0)
    //     const fullPath = this.#resolvedPath(path)
    //     return xattr.get(fullPath, name)
    // }

    // async listxattr(path) {
    //     return xattr.list(path)
    // }

    // async removexattr(path, name) {
    //     return xattr.remove(path, name)
    // }

    async open(path, flags) {
        if (ignored(path)) throw new FSError(Fuse.ENOENT)

        const fullPath = this.#resolvedPath(path)
        const fd = await fsFns.open(fullPath, flags)
        const capabilities = await this.keyRing.getCapabilitiesWithRelativePath(path)

        const filehandle = new FileHandle({ fd, path: fullPath, capabilities })
        this.handles.set(fd, filehandle)
        return fd
    }

    // Called when a file descriptor is being released.Happens when a read/ write is done etc.
    async release(path, fd) {
        if (ignored(path)) throw new FSError(Fuse.ENOENT)
        this.handles.delete(fd)
    }

    // Same as release but for directories.
    async releasedir(path, fd) {
        return this.release(path, fd)
    }

    // async opendir(path, flags) {
    //     const dir = await fs.opendir(path, flags)
    // }

    async read(path, fd, buffer, length, position) {
        if (ignored(path) || !this.handles.has(fd)) throw new FSError(Fuse.ENOENT)
        const handle = this.handles.get(fd)
        return await handle.read(buffer, length, position)
    }

    async write(path, fd, buffer, length, position) {
        if (ignored(path) || !this.handles.has(fd)) throw new FSError(Fuse.ENOENT)
        const handle = this.handles.get(fd)
        const bytesWritten = await handle.write(buffer, length, position)
        await prependSignature(handle)
        return bytesWritten
    }

    // Create and open file
    async create(path, mode) {
        if (ignored(path)) throw new FSError(Fuse.ENOENT)
        // 'wx+': Open file for reading and writing. Creates file but fails if the path exists.
        const fullPath = this.#resolvedPath(path)
        const fd = await fsFns.open(fullPath, "wx+", mode)

        const capabilities = await this.keyRing.createNewCapabilitiesForRelativePath(path)

        const filehandle = new FileHandle({ fd, path: fullPath, capabilities })
        await prependSignature(filehandle)
        this.handles.set(fd, filehandle)
        return fd
    }

    async utimens(path, atime, mtime) {
        return fs.utimes(this.#resolvedPath(path), new Date(atime), new Date(mtime))
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
    FuseHandlers
}
