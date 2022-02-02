const chokidar = require("chokidar")
const path = require("path")
const EventEmitter = require("events")
const fs = require("fs/promises")
const { createReadStream } = require("fs")
const queue = require("async/queue")
const { relative } = require("path")
const { Dropbox } = require("dropbox")
const fsFns = require("../fsFns")
const dch = require("../dropbox-content-hasher")

/// IntegrityChecker reacts to changes on 'watchPatch' (intended to be the dropbox-client)
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

    constructor({ watchPath, keyring }) {
        super()
        this._db = new Dropbox({ accessToken: "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W" })
        this._watchPath = watchPath
        this._keyring = keyring

        // We use a job-queue for the rollback-jobs.
        // Jobs are 'push'ed onto the queue and handled by a single worker.
        // The worker (the callback below) restores the invalid file to its latest valid state
        this._jobQueue = queue(async job => {
            // Performance optimization: If an equivalent job is already pending,
            // then it will perform the rollback that this job requests.
            // Thus this job is reduntant and we can mark it as completed prematurely.
            // This is purely a performance optimization.
            if (this._equivalentJobIsPending(job)) {
                this.emit(EQUIVALENT_CONFLICT_IS_PENDING, job)
            }

            const didPerformRollback = await this._performFileRestoreIfNecessary(job)
            if (didPerformRollback) {
                this.emit(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, job)
            } else {
                this.emit(IntegrityChecker.NO_CONFLICT, job)
            }
        })

        // This is called if any worker fails (e.g throws an error)
        this._jobQueue.error((error, job) => {
            this.emit(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, { error, ...job })
        })

        // setup watcher
        this._watcher = chokidar.watch(watchPath, {
            ignored: /(^|[\/\\])\../, // ignore dotfiles
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
    }

    async stopWatching() {
        await this._watcher.close()
    }

    async _verifyFile({ localPath, remotePath }) {
        const verifyCapability = await this._keyring.getCapabilityWithPathAndType(remotePath, "verify")
        if (!verifyCapability) return true // we accept files we cannot check.

        const contentHash = await contentHash(localPath)

        if (await fileAtPathMarkedAsDeleted(localPath)) {
            const latestRevisionID = await fetchLatestRevisionID(remotePath)
            const verified = verifyDeleteFileContent(content, verifyCapability.key, latestRevisionID)
            console.log(timestamp(`${remotePath}: marked as deleted. Verified: ${verified}`))
            return verified
        } else {
            // is a regular write-operation: verify the signature
            // compute the hash from the macs in all chunks
            const macHash = await macHash(localPath)

            const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
            await fsFns.read(fd, expectedSignature, 0, sodium.crypto_sign_BYTES, SIGNATURE_MARK.length)

            return verifyDetached(signature, digest, verifyCapability.key)
        }
    }

    /** Checks if the modified file at 'localPath' satisfies the predicate given in the constructor
     *  If not, the file at 'localPath' is restored to the latest revision which satisfy 'predicate'.
     *
     * @param {string} localPath
     */
    async _checkIfRollbackNeeded(localPath, opts) {
        const remotePath = path.relative(this._watchPath, localPath)
        const job = {
            ...opts,
            localPath,
            remotePath
        }

        this.emit(IntegrityChecker.CHANGE, job)
        const verified = await this._predicate({ localPath, remotePath })

        if (verified) {
            this.emit(IntegrityChecker.NO_CONFLICT, job)
        } else {
            this.emit(IntegrityChecker.CONFLICT_FOUND, job)
            this._jobQueue.push(job)
        }
    }

    /**
     *
     * @param {} remotePath - the remote path of the file to restore. Is optional if 'localPath' is present
     * @param {} localPath - the local path of the file to restore. Is optional if 'remotePath' is present
     * @returns {Promise<boolean>} Resolves with 'true' to indicate a successful restore was performed.
     * Resolves with 'false' to indicate a restore was not necessary
     * Rejects with error if none of the revisions satisfy the predicate or if a read/write/download error occur.
     */
    async _performFileRestoreIfNecessary({ remotePath }) {
        const localPath = path.join(this._watchPath, remotePath)

        // check if the file has been changed since the rollback was scheduled to avoid to make an unnecessary restore
        if (await this.isLocalContentVerified({ localPath })) return false // conflict already resolved by FSP-client. Mark no conflict is needed

        const { entries: revisions } = await this._fsp.listRevisions(remotePath)

        for (const revision of revisions) {
            if (await this.isLocalContentVerified({ localPath })) return false // conflict already resolved by FSP-client. Mark no conflict is needed

            const remoteContent = await this._fsp.downloadRevision(revision.rev)

            //HER OPSTÅR FEJLEN. PREDICATE SKAL OGSÅ KUNNE BENYTTES PÅ 'REMOTECONTENT' - MEN HVAD HVIS 'REMOTECONTENT' ER STOR? TJEK OP
            const verified = await this._predicate({ content: remoteContent, remotePath })

            if (verified) {
                if (await this.isLocalContentVerified({ localPath })) return false // conflict already resolved by FSP-client. Mark no conflict is needed

                await this._fsp.restoreFile(remotePath, revision.rev)
                return true // mark rollback performed successfylly
            }
        }

        throw new Error("None of the " + revisions.length + " revisions met the predicate.")
    }

    async isLocalContentVerified({ localPath }) {
        try {
            localContent = await fs.readFile(localPath)
            return await this._predicate({ content: localContent, remotePath: relative(this._watchPath, localPath) })
        } catch {
            return false // a deleted file cannot be verified
        }
    }

    _equivalentJobIsPending(job) {
        const pendingJobs = [...this._jobQueue]
        return pendingJobs.some(j => j.remotePath === job.remotePath)
    }

    _onAdd(localPath) {
        this._checkIfRollbackNeeded(localPath, { eventType: "add" })
    }

    _onChange(localPath) {
        this._checkIfRollbackNeeded(localPath, { eventType: "change" })
    }

    _onUnlink(localPath) {
        this._checkIfRollbackNeeded(localPath, { eventType: "unlink" })
    }
}

const contentHash = async localPath => {
    return new Promise((resolve, reject) => {
        const hasher = dch.create()
        const stream = createReadStream(localPath)
        stream.on("data", data => hasher.update(data))
        stream.on("end", () => resolve(hasher.digest("hex")))
        stream.on("error", err => reject(err))
    })
}

const macHash = async localPath => {
    const hash = createHash("sha256")
    const fd = await fsFns.open(localPath, "r")
    const size = (await fsFns.fstat(fd)).size

    const chunkCount = Math.ceil(size / STREAM_CIPHER_CHUNK_SIZE) // ceil to include the last (potentially) non-full chunk
    const offset = TOTAL_SIGNATURE_SIZE + sodium.crypto_secretbox_NONCEBYTES

    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
        const start = chunkIndex * STREAM_CIPHER_CHUNK_SIZE + offset
        const mac = Buffer.alloc(sodium.crypto_secretbox_MACBYTES)
        await fsFns.read(fd, mac, 0, sodium.crypto_secretbox_MACBYTES, start)
        hash.update(mac)
    }

    return hash.digest("hex")
}

module.exports = IntegrityChecker
