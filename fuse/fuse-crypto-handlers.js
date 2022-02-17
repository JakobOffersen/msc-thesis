const fs = require("fs/promises")
const { join, basename, dirname, extname } = require("path")
const sodium = require("sodium-native")
const fsFns = require("../fsFns.js")
const Fuse = require("fuse-native")
const FileHandle = require("./file-handle")
const lock = require("fd-lock")
const { CAPABILITY_TYPE_WRITE, STREAM_CIPHER_CHUNK_SIZE, SIGNATURE_SIZE } = require("../constants.js")
const { createDeleteFileContent } = require("../file-delete-utils.js")
const FSError = require("./fs-error.js")

function ignored(path) {
    return basename(path).startsWith("._")
}
/**
 * Computes the size of a plaintext message based on the size of the file on disk.
 * @param {number} fileLength
 * @returns size in bytes
 */
function plaintextLength(fileLength) {
    fileLength -= SIGNATURE_SIZE

    const chunkCount = Math.ceil(fileLength / STREAM_CIPHER_CHUNK_SIZE)
    const tagSizes = chunkCount * (sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES)

    return Math.max(fileLength - tagSizes, 0) // some resource forks are not signed, since they are not created through the mount-point. All files should be of least size 0.
}

async function withFileLock(fd, fn) {
    lock(fd)
    try {
        const res = await fn()
        return res
    } finally {
        lock.unlock(fd)
    }
}

class FuseHandlers {
    constructor(baseDir, keyring, debug = false) {
        this.baseDir = baseDir
        this.keyring = keyring
        this.debug = debug

        // Maps file descriptors (numbers) to FileHandles
        this.handles = new Map()
    }

    /**
     * Resolve a relative path to its location in the FSP directory.
     * For example, /hello.txt becomes /Users/[Username]/Dropbox/hello.txt.
     */
    #resolvedPath(path) {
        return join(this.baseDir, path)
    }

    async #ensureCapability(path, capabilityType) {
        const capability = await this.keyring.getCapabilityWithPathAndType(path, capabilityType)
        if (!capability) throw new FSError(Fuse.EACCES)
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
        if (stat.isFile()) {
            stat.size = plaintextLength(stat.size)
        }

        if (this.debug) console.log(`getattr ${path}, size ${stat.size}`)
        return stat
    }

    async fsync(path, fd, datasync) {
        if (datasync) {
            return fsFns.fdatasync(fd)
        } else {
            return fsFns.fsync(fd)
        }
    }

    async fsyncdir(path, fd, datasync) {
        return this.fsync(path, fd, datasync)
    }

    async readdir(path) {
        const fullPath = this.#resolvedPath(path)
        const files = await fs.readdir(fullPath)
        return files.filter(file => extname(file) !== ".deleted" && file !== "users") // ignore .deleted files and /users/* (postal boxes)
    }

    async truncate(path, size) {
        if (this.debug) console.log(`truncate ${path} to size ${size}`)

        const mode = 2 // fs.constants.O_RDWR
        const fd = await this.open(path, mode)
        const handle = this.handles.get(fd)

        if (!handle.writeCapability) throw new FSError(Fuse.EACCES) // the user is not allowed to perform the operation.

        try {
            await withFileLock(fd, async () => {
                if (size === 0) {
                    // FUSE is requesting we truncate the whole file. Only the signature is left behind.
                    await fsFns.ftruncate(fd, SIGNATURE_SIZE)
                    await handle.createSignature()
                } else {
                    // Read the contents that should be kept
                    const contents = Buffer.alloc(size)
                    await handle.read(contents, size, 0)

                    const fullPath = this.#resolvedPath(path)
                    // Truncate the file
                    await fsFns.truncate(fullPath, SIGNATURE_SIZE)

                    // Write the saved contents
                    await handle.write(contents, size, 0)

                    // Create signature
                    await handle.createSignature()
                }
            })
        } finally {
            // Close file descriptor
            await this.release(path, fd)
            await fsFns.close(fd)
        }
    }

    async chown(path, uid, gid) {
        const fullPath = this.#resolvedPath(path)
        return fs.chown(fullPath, uid, gid)
    }

    async chmod(path, mode) {
        const fullPath = this.#resolvedPath(path)
        return fs.chmod(fullPath, mode)
    }

    async open(path, flags) {
        if (this.debug) console.log(`open ${path}`)
        if (ignored(path)) throw new FSError(Fuse.ENOENT)

        const capabilities = await this.keyring.getCapabilitiesWithPath(path)
        const fullPath = this.#resolvedPath(path)
        const fd = await fsFns.open(fullPath, flags)

        const handle = new FileHandle(fd, capabilities)
        this.handles.set(fd, handle)

        return fd
    }

    // Called when a file descriptor is being released.
    async release(path, fd) {
        if (this.debug) console.log(`release ${path}`)
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
        if (this.debug) console.log(`read ${path} len ${length} pos ${position}`)

        const handle = this.handles.get(fd)
        const bytesRead = await handle.read(buffer, length, position)
        if (this.debug) console.log(`\t bytes read ${bytesRead}`)
        return bytesRead
    }

    async write(path, fd, buffer, length, position) {
        if (ignored(path) || !this.handles.has(fd)) throw new FSError(Fuse.ENOENT)
        if (this.debug) console.log(`write ${path} len ${length} pos ${position}`)
        const handle = this.handles.get(fd)

        if (!handle.writeCapability) throw new FSError(Fuse.EACCES) // the user is not allowed to perform the operation.

        // We lock the file to ensure no other process (e.g. the daemon) interacts with the
        // file in the time-frame between writing the content and writing the signature
        return await withFileLock(fd, async () => {
            const bytesWritten = await handle.write(buffer, length, position)
            if (this.debug) console.log(`\tbytes written ${bytesWritten}`)
            await handle.createSignature()
            if (this.debug) console.log(`\created signature`)
            return bytesWritten
        })
    }

    // Create and open file
    async create(path, mode) {
        if (this.debug) console.log(`create ${path}`)

        if (ignored(path)) throw new FSError(Fuse.ENOENT)
        // 'wx+': Open file for reading and writing. Creates file but fails if the path exists.
        const fullPath = this.#resolvedPath(path)
        const fd = await fsFns.open(fullPath, "wx+", mode)

        const parentName = basename(dirname(path)) // for 'x/y/z.txt' this returns 'y'
        const grandparent = dirname(dirname(path)) // for 'a/b/c/d' this returns 'a/b'
        const cleanedBasename = basename(path).split(".").slice(0, 2).join(".") // remove potential suffixes starting with "." Eg "/picture.jpg.sb-ab52335b-nePMlX" becomes "picture.jpg"
        let capabilities
        if (parentName.startsWith(cleanedBasename)) {
            capabilities = await this.keyring.getCapabilitiesWithPath(join("/", grandparent, cleanedBasename))
        } else {
            capabilities = await this.keyring.createNewCapabilitiesForRelativePath(path)
        }

        const handle = new FileHandle(fd, capabilities)
        this.handles.set(fd, handle)

        await handle.createSignature()

        return fd
    }

    async utimens(path, atime, mtime) {
        return fs.utimes(this.#resolvedPath(path), new Date(atime), new Date(mtime))
    }

    async unlink(path) {
        const fullPath = this.#resolvedPath(path)
        if (ignored(path)) return await fs.unlink(fullPath)

        // Deleting a file requires write capabilities for that file
        await this.#ensureCapability(path, CAPABILITY_TYPE_WRITE)

        const content = createDeleteFileContent({ localPath: fullPath, remotePath: path, writeKey: writeCapability.key })

        // Truncate the file when opening a file descriptor.
        const fd = await this.open(path, fs.constants.O_RDWR | fs.constants.O_TRUNC)

        try {
            await fsFns.write(fd, content, 0, content.length, 0)
            await fs.rename(fullPath, fullPath + ".deleted") // Mark the file with an extension to more easily distinguish it from non-deleted files.
        } finally {
            // Close file descriptor
            await this.release(path, fd)
            await fsFns.close(fd)
        }
    }

    async rename(src, dest) {
        throw Fuse.EIO
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
        try {
            return fs.rmdir(this.#resolvedPath(path))
            return fs.rm(this.#resolvedPath(path), { recursive: false })
        } catch (error) {
            console.log(error)
            throw error
        }
    }
}

module.exports = {
    FuseHandlers
}
