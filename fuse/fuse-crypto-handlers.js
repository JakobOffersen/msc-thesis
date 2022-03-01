const fs = require("fs/promises")
const { constants: fsConstants } = require("fs")
const { join, basename, dirname, extname } = require("path")
const sodium = require("sodium-native")
const { statvfs } = require("@wwa/statvfs")
const lock = require("fd-lock")
const fsFns = require("../fsFns.js")
const Fuse = require("fuse-native")
const FileHandle = require("./file-handle")
const { CAPABILITY_TYPE_WRITE, STREAM_CIPHER_CHUNK_SIZE, SIGNATURE_SIZE, BASE_DIR, CAPABILITY_TYPE_VERIFY, POSTAL_BOX_SHARED } = require("../constants.js")
const { createDeleteFileContent } = require("../file-delete-utils.js")
const FSError = require("./fs-error.js")
const { v4: uuidv4 } = require("uuid")

function ignored(path) {
    return basename(path).startsWith("._") || path === "/.DS_Store" || basename(path).startsWith(".fuse_hidden")
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

/**
 * Locks the file referenced by the provided file descriptor and
 * calls the provided function.
 */
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

    /**
     * Provides information about the file system.
     * We obtain this information from the file system on which the FSP directory resides.
     */
    async statfs(path) {
        const res = await statvfs(BASE_DIR)

        return {
            ...res,
            frsize: res.bsize,
            favail: res.bavail,
            fsid: 42, // File system ID. See https://man7.org/linux/man-pages/man2/statfs.2.html
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

        const fd = await this.open(path, fsConstants.O_RDWR)
        const handle = this.handles.get(fd)

        try {
            if (!handle.writeCapability) throw new FSError(Fuse.EACCES) // the user is not allowed to perform the operation.

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

    /**
     * Create a file and return a file descriptor for it.
     * If a file already exists at the provided path, an error is thrown.
     * Capabilities are added to the users keyring.
     */
    async create(path, mode) {
        if (this.debug) console.log(`create ${path}`)
        if (ignored(path)) throw new FSError(Fuse.ENOENT)

        // Determine if this an "ephemeral" file. If so, it should share capabilities
        // with the real file that it represents.
        const parentName = basename(dirname(path)) // for 'x/y/z.txt' this returns 'y'
        const grandparent = dirname(dirname(path)) // for 'a/b/c/d' this returns 'a/b'
        const cleanedBasename = basename(path).split(".").slice(0, 2).join(".") // remove potential suffixes starting with "." Eg "/picture.jpg.sb-ab52335b-nePMlX" becomes "picture.jpg"
        let capabilities
        if (parentName.startsWith(cleanedBasename)) {
            // The 'path' represents a resource-fork or ephemeral file. Re-use the capabilities attached to the original file.
            capabilities = await this.keyring.getCapabilitiesWithPath(join("/", grandparent, cleanedBasename))
        } else {
            // The 'path' represents a new file (not ephemeral/resource fork).
            // Check if the file has already been created before (FUSE always calls 'create' twice for the same new path)
            // If there already exist capabilities for the file, we re-use those. Otherwise we generate new capabilities
            const existingCapabilities = await this.keyring.getCapabilitiesWithPath(path)
            if (existingCapabilities.length > 0) {
                capabilities = existingCapabilities // use the existing capabilities
            } else {
                // no capabilities exist for this path. Generate new
                capabilities = await this.keyring.createNewCapabilitiesForRelativePath(path)

                // Write the newly generated verify-key to the shared postal box
                let { ...verifyCapability } = capabilities.find(cap => cap.type === CAPABILITY_TYPE_VERIFY) // clone the cap to avoid side effects
                verifyCapability.key = verifyCapability.key.toString("hex")
                const capabilityLocalFilename = join(BASE_DIR, POSTAL_BOX_SHARED, uuidv4() + ".capability") // use a random basename to avoid name conflicts
                try {
                    await fs.writeFile(capabilityLocalFilename, JSON.stringify(verifyCapability))
                } catch {
                    // the postal box has not been created. Create it
                    await fs.mkdir(join(BASE_DIR, POSTAL_BOX_SHARED), { recursive: true })
                    await fs.writeFile(capabilityLocalFilename, JSON.stringify(verifyCapability))
                }
            }
        }

        // 'wx+': Open file for reading and writing. Creates file but fails if the path exists.
        const fullPath = this.#resolvedPath(path)
        const fd = await fsFns.open(fullPath, "wx+", mode)

        // Ensure that the file has a signature.
        const handle = new FileHandle(fd, capabilities)
        await handle.createSignature()

        this.handles.set(fd, handle)

        return fd
    }

    /**
     * Return timestamps for the file
     */
    async utimens(path, atime, mtime) {
        return fs.utimes(this.#resolvedPath(path), new Date(atime), new Date(mtime))
    }

    /**
     * Delete a file.
     * This means replacing file contents with a signed marker and renaming the file.
     */
    async unlink(path) {
        const fullPath = this.#resolvedPath(path)
        if (ignored(path)) return await fs.unlink(fullPath)

        // Deleting a file requires write capabilities for that file.
        await this.#ensureCapability(path, CAPABILITY_TYPE_WRITE)

        const writeCapability = await this.keyring.getCapabilityWithPathAndType(path, CAPABILITY_TYPE_WRITE)

        const content = createDeleteFileContent(writeCapability.key, path)
        // Truncate the file when opening a file descriptor.
        const fd = await this.open(path, fsConstants.O_RDWR | fsConstants.O_TRUNC)

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
        //throw Fuse.EIO // we cannot throw .EIO as macOS calls 'rename' when making ephmeral files. By throwing .EIO (all?) Apples applications will fail
        return fs.rename(this.#resolvedPath(src), this.#resolvedPath(dest))
    }

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
