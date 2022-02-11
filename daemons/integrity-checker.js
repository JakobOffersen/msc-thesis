const chokidar = require("chokidar")
const EventEmitter = require("events")
const fs = require("fs/promises")
const { createReadStream } = require("fs")
const queue = require("async/queue")
const { basename, dirname, extname, relative } = require("path")
const { Dropbox } = require("dropbox")
const fsFns = require("../fsFns")
const dch = require("../dropbox-content-hasher")
const sodium = require("sodium-native")
const { verifyCombined, verifyDetached, decryptWithPublicKey, Hasher } = require("../crypto")
const { fileAtPathMarkedAsDeleted } = require("../file-delete-utils")
const { STREAM_CIPHER_CHUNK_SIZE, SIGNATURE_SIZE, FSP_ACCESS_TOKEN, FILE_DELETE_PREFIX_BUFFER } = require("../constants")
const debounce = require("debounce")
const { inversePromise } = require("../test/testUtil")

/// IntegrityChecker reacts to changes on 'watchPath' (intended to be the dropbox-client)
/// and verifies each change against 'predicate'.
/// If a changed file doesn't satisfy 'predicate', the changed file is restored
/// to its latest revision which satisfies 'predicate'.
/// Throughout its lifetime, relevant events are emitted for the caller to listen to.
class IntegrityChecker extends EventEmitter {
    // EVENT NAMES
    static READY = "ready"
    static CHANGE = "change"
    static NO_CONFLICT = "no-conflict"
    static CONFLICT_FOUND = "conflict-found"
    static CONFLICT_RESOLUTION_FAILED = "conflict-resolution-failed"
    static CONFLICT_RESOLUTION_SUCCEEDED = "conflict-resolution-succeeded"
    static EQUIVALENT_CONFLICT_IS_PENDING = "equivalent-conflict-is-pending"

    constructor({ watchPath, keyring, username }) {
        super()
        this._db = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })
        this._watchPath = watchPath
        this._keyring = keyring
        this._username = username

        // setup watcher
        this._watcher = chokidar.watch(watchPath, {
            ignored: function (path) {
                // ignore dot-files and ephemeral files creates by the system
                return (
                    path.match(/(^|[\/\\])\../) ||
                    basename(dirname(path)).split(".").length > 2 || // eg "file3.txt.sb-ab52335b-BlLaP1/file3.txt"
                    (basename(path).split(".").length > 2 && extname(path) !== ".deleted") || // eg "/milky-way-nasa.jpg.sb-ab52335b-jqZvPa/milky-way-nasa.jpg.sb-ab52335b-j7X3TY"
                    (path.includes("/users/") && !path.includes("/users/" + this._username)) // ignore all postal boxes except for your own postal box. TODO: make into regex for better performance?
                )
            }.bind(this),
            persistent: true // indicates that chokidar should continue the process as long as files are watched
        })
        // Chokiar emits 'add' for all existing files in the watched directory
        // To only watch for future changes, we only add our 'add' listener after
        // the initial scan has occured.
        this._watcher.on("ready", () => {
            this._watcher.on("add", this._onAdd.bind(this))
            this._watcher.on("change", this._onChange.bind(this))
            this._watcher.on("unlink", this._onUnlink.bind(this))
            this.emit(IntegrityChecker.READY)
        })

        // We use a job-queue for the rollback-jobs.
        // Jobs are 'push'ed onto the queue and handled by a single worker.
        // The worker (the callback below) restores the invalid file to its latest valid state
        this._jobQueue = queue(async job => {
            // Performance optimization: If an equivalent job is already pending,
            // then it will perform the rollback that this job requests.
            // Thus this job is reduntant and we can mark it as completed prematurely.
            // This is purely a performance optimization.
            if (this._equivalentJobIsPending(job)) return this.emit(IntegrityChecker.EQUIVALENT_CONFLICT_IS_PENDING, job)

            const verified = await this._verify(job)

            if (verified) return this.emit(IntegrityChecker.NO_CONFLICT, job)

            this.emit(IntegrityChecker.CONFLICT_FOUND, job)

            try {
                await this._rollback(job)
            } catch (error) {
                console.trace()
                throw error
            }

            this.emit(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, job)
        })

        // This is called if any worker fails (e.g throws an error)
        this._jobQueue.error((error, job) => {
            this.emit(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, { error, ...job })
        })

        this.debouncers = new Map() // maps from localPath to debouce
    }

    async stopWatching() {
        await this._watcher.close()
    }

    async _verify({ localPath, remotePath, eventType }) {
        const verifyCapability = await this._keyring.getCapabilityWithPathAndType(remotePath, "verify")
        if (!verifyCapability) return true // we accept files we cannot check.

        if (extname(localPath) === ".deleted" && eventType === "unlink") return false // we dont allow .deleted files to be deleted

        try {
            const hasDeleteMark = await fileAtPathMarkedAsDeleted(localPath) // throws if the file does not exist

            if (hasDeleteMark) {
                // step 1)
                // A valid delete follows the schema:
                //      <delete-prefix><signature(revisionID)>
                // where 'revisionID' denotes the latest revision ID of the file before it was marked as deleted
                // Thus we accept the file-delete iff
                // 1) the prefix is present and correct AND
                // 2) the signature is present and correct AND
                // 3) the signed message is the revision ID of the file just before the file marked as deleted

                // read the signature from the file
                if (extname(localPath) !== ".deleted") localPath = localPath + ".deleted"
                const content = await fs.readFile(localPath)
                const signedMessage = content.subarray(FILE_DELETE_PREFIX_BUFFER.length)
                const { verified, message } = verifyCombined(signedMessage, verifyCapability.key)

                if (!verified) return false // the signature is not valid. No need to check further

                const expectedRevision = await this.revisionBeforeCurrentRevision({ localPath, remotePath: remotePath.replace(".deleted", "") })
                return Buffer.compare(message, Buffer.from(expectedRevision.rev, "hex")) === 0
            } else {
                // is a regular write-operation: verify the signature
                // compute the hash from the macs in all chunks
                const hash = await ciphertextHash(localPath)
                const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
                const fd = await fsFns.open(localPath, "r")
                await fsFns.read(fd, signature, 0, signature.length, 0)
                const verified = verifyDetached(signature, hash, verifyCapability.key)

                return verified
            }
        } catch (error) {
            // -2 : file does not exist => file must have been deleted => cannot be verified
            if (error.errno === -2) {
                return false
            } else {
                console.trace()
                throw error
            }
        }
    }

    async revisionBeforeCurrentRevision({ localPath, remotePath, contentHash, retries = 0 } = {}) {
        if (retries === 10) throw new Error(`Cannot compute current revision for ${remotePath}. Retries: ${retries}`)

        // Find the index of the current revision. The revision used for the message must be just before the current one
        // We need this step to handle a race condition in which we fetch for revisions of the file before Dropbox
        // has received the latest revision that we has marked as deleted.

        if (!contentHash) contentHash = await dropboxContentHash(localPath)

        const response = await this._db.filesListRevisions({ path: remotePath, mode: "path" })
        const entries = response.result.entries
        // Find the index of the current revision. The revision used for the message must be just before the current one
        // We need this step to handle a race condition in which we fetch for revisions of the file before Dropbox
        // has received the latest revision that we has marked as deleted.
        const currentRevisionIndex = entries.findIndex(entry => entry.content_hash === contentHash)

        if (currentRevisionIndex !== -1) return entries[currentRevisionIndex + 1] // return the revision before the current one

        // FSP has not received the deleted version of the file.
        // backoff and try again
        const { promise, resolve } = inversePromise()
        console.log(`revisionBeforeCurrentRevision retry ${retries + 1}`)
        setTimeout(resolve, 2000) // wait for two seconds
        await promise
        return this.revisionBeforeCurrentRevision({ localPath, remotePath, retries: retries + 1 })
    }

    /** Checks if the modified file at 'localPath' satisfies the predicate given in the constructor
     *  If not, the file at 'localPath' is restored to the latest revision which satisfy 'predicate'.
     *
     * @param {string} localPath
     */
    async _pushJob(localPath, opts) {
        const remotePath = "/" + relative(this._watchPath, localPath)
        const job = { localPath, remotePath, ...opts }
        this._jobQueue.push(job)
    }

    /**
     *
     * @param {} remotePath - the remote path of the file to restore. Is optional if 'localPath' is present
     * @param {} localPath - the local path of the file to restore. Is optional if 'remotePath' is present
     */
    async _rollback({ localPath, remotePath, eventType }) {
        if (extname(localPath) === ".deleted" && eventType === "unlink") {
            // a '.deleted' file has been deleted
            const response = await this._db.filesListRevisions({ path: remotePath, mode: "path", limit: 10 })
            console.log(`_rollback .deleted && unlink: ${response.status}, remote path ${remotePath}`)
            const entries = response.result.entries
            entries.forEach(e => console.log(e.rev))
            await this.fileRestore({ remotePath, rev: entries[0].rev })
        } else {
            remotePath = remotePath.replace(".deleted", "") // TODO: explain why we remove the extension here

            try {
                const revisionToRestoreTo = await this.revisionBeforeCurrentRevision({ localPath, remotePath })
                await this.fileRestore({ remotePath, rev: revisionToRestoreTo.rev })
            } catch (error) {
                if (error.errno !== -2) throw error
                const response = await this._db.filesListRevisions({ path: remotePath, mode: "path", limit: 10 })
                await this.fileRestore({ remotePath, rev: response.result.entries[1].rev })
            }
        }
    }

    async fileRestore({ remotePath, rev, retries = 0 } = {}) {
        if (retries === 10) throw new Error(`failed restoring ${remotePath}. Tried ${retries} times`)

        console.log(`retoring ${remotePath}, retries: ${retries + 1}, rev: ${rev}`)
        try {
            const response = await this._db.filesRestore({ path: remotePath, rev: rev }) // a delete is *not* considered a revision in Dropbox. Therefore we should restore the latest version (index 1)
            console.log(`restored ${remotePath} ${response.result.rev}`)
        } catch {
            const { resolve, promise } = inversePromise()
            setTimeout(resolve, 2000)
            await promise
            await this.fileRestore({ remotePath, rev, retries: retries + 1 })
        }
    }

    _equivalentJobIsPending({ remotePath }) {
        const pendingJobs = [...this._jobQueue]
        return pendingJobs.some(job => job.remotePath === remotePath)
    }

    _onAdd(localPath) {
        if (localPath.includes("/users/" + this._username)) {
            this._checkPostalbox(localPath)
        } else {
            this._debouncePushJob(localPath, { eventType: "add" })
        }
    }

    _onChange(localPath) {
        if (localPath.includes("/users/" + this._username)) return // ignore changes made in ones own postal box
        this._debouncePushJob(localPath, { eventType: "change" })
    }

    _onUnlink(localPath) {
        if (localPath.includes("/users/" + this._username)) return // ignore deletes made in ones own postal box
        this._debouncePushJob(localPath, { eventType: "unlink" })
    }

    _debouncePushJob(...args) {
        const localPath = args[0]
        if (!this.debouncers.has(localPath)) this.debouncers.set(localPath, debounce(this._pushJob.bind(this), 1000))
        const debounced = this.debouncers.get(localPath)
        debounced(...args)
    }

    async _checkPostalbox(localPath) {
        try {
            const { sk, pk } = await this._keyring.getUserKeyPair()
            const content = await fs.readFile(localPath)
            const decrypted = decryptWithPublicKey(content, pk, sk)
            const capabilities = JSON.parse(decrypted)

            for (const capability of capabilities) {
                await this._keyring.addCapability(capability)
                console.log(`added capability ${capability.type} for ${capability.path} to keyring`)
            }
        } catch (error) {
            console.log(`checkPostalbox ERROR: ${error}`)
        }
    }
}

// A hash of the entire file content computed in the same way that Dropbox
// computes their 'content_hash'.
const dropboxContentHash = async localPath => {
    return new Promise((resolve, reject) => {
        //TODO: lock while hashing?
        const hasher = dch.create()
        const stream = createReadStream(localPath)
        stream.on("data", data => hasher.update(data))
        stream.on("end", () => resolve(hasher.digest("hex")))
        stream.on("error", err => reject(err))
    })
}

// A hash of the content computed in the same way that we compute the hash in FUSE
const ciphertextHash = async localPath => {
    //TODO: Lock while reading macs?
    const hasher = new Hasher()
    const fd = await fsFns.open(localPath, "r")

    // Compute hash of entire file except the signature in the
    // same block size as they were written.
    const cipherSize = (await fsFns.fstat(fd)).size - SIGNATURE_SIZE
    const chunkCount = Math.ceil(cipherSize / STREAM_CIPHER_CHUNK_SIZE)
    const offset = SIGNATURE_SIZE

    let read = 0
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
        const start = chunkIndex * STREAM_CIPHER_CHUNK_SIZE + offset
        const blockSize = Math.min(STREAM_CIPHER_CHUNK_SIZE, cipherSize - read)
        const block = Buffer.alloc(blockSize)
        await fsFns.read(fd, block, 0, block.length, start)
        hasher.update(block)
        read += blockSize
    }

    return hasher.final()
}

module.exports = IntegrityChecker
