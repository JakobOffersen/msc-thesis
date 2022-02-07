const chokidar = require("chokidar")
const path = require("path")
const EventEmitter = require("events")
const fs = require("fs/promises")
const { createReadStream } = require("fs")
const queue = require("async/queue")
const { relative, basename, dirname } = require("path")
const { Dropbox } = require("dropbox")
const fsFns = require("../fsFns")
const dch = require("../dropbox-content-hasher")
const sodium = require("sodium-native")
const { FILE_DELETE_PREFIX_BUFFER } = require("../constants")
const { verifyCombined, verifyDetached } = require("../crypto")
const { fileAtPathMarkedAsDeleted } = require("../file-delete-utils")
const { createHash } = require("crypto")
const { STREAM_CIPHER_CHUNK_SIZE, TOTAL_SIGNATURE_SIZE, SIGNATURE_MARK } = require("../constants")
const debounce = require("debounce")

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

        // setup watcher
        this._watcher = chokidar.watch(watchPath, {
            ignored: function (path) {
                // ignore dot-files and ephemeral files creates by the system
                return (
                    path.match(/(^|[\/\\])\../) ||
                    basename(dirname(path)).split(".").length > 2 || // (eg "file3.txt.sb-ab52335b-BlLaP1/file3.txt")
                    basename(path).split(".").length > 2 // "/milky-way-nasa.jpg.sb-ab52335b-jqZvPa/milky-way-nasa.jpg.sb-ab52335b-j7X3TY"
                )
            },
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

            await this._rollback(job)

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

    async _verify({ localPath, remotePath }) {
        const verifyCapability = await this._keyring.getCapabilityWithPathAndType(remotePath, "verify")
        if (!verifyCapability) return true // we accept files we cannot check.

        try {
            const hasDeleteMark = await fileAtPathMarkedAsDeleted(localPath) // throws if the file does not exist

            if (hasDeleteMark) {
                // A valid delete follows the schema:
                //      <delete-prefix><signature(revisionID)>
                // where 'revisionID' denotes the latest revision ID of the file before it was marked as deleted
                // Thus we accept the file-delete iff
                // 1) the prefix is present and correct AND (which is checked by 'fileAtPathMarkedAsDeleted')
                // 2) the signature is present and correct AND
                // 3) the signed message is the revision ID of the file just before the file marked as deleted

                // read the signature from the file
                const content = await fs.readFile(localPath)
                const signedMessage = content.subarray(FILE_DELETE_PREFIX_BUFFER.length)
                const { verified, message } = verifyCombined(signedMessage, verifyCapability.key)

                if (!verified) return false // the signature is not valid. No need to check further
                // fetch the revisionID of the file.
                const response = await this._db.filesListRevisions({ path: remotePath, mode: "path" })
                const entries = response.result.entries
                // TODO: This step is prone to a race condition in which the remote file is changed in between the local file trigger and the list of revisions we fetch above.
                // Fix this by computing the revision ID (based on the content hash) of the current file and choosing the revision ID just after that value
                const revisionID = entries[1].rev // entry '0' is the version of the file => entry '1' is the revision that is marked as downloaded

                return Buffer.compare(message, Buffer.from(revisionID)) === 0
            } else {
                // is a regular write-operation: verify the signature
                // compute the hash from the macs in all chunks
                const macDigest = await macHash(localPath)
                const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
                const fd = await fsFns.open(localPath, "r")
                await fsFns.read(fd, signature, 0, signature.length, SIGNATURE_MARK.length)
                const verified = verifyDetached(signature, macDigest, verifyCapability.key)

                return verified
            }
        } catch (error) {
            // -2 : file does not exist => file must have been deleted => cannot be verified
            if (error.errno === -2) {
                return false
            } else {
                throw error
            }
        }
    }

    /** Checks if the modified file at 'localPath' satisfies the predicate given in the constructor
     *  If not, the file at 'localPath' is restored to the latest revision which satisfy 'predicate'.
     *
     * @param {string} localPath
     */
    async _pushJob(localPath, opts) {
        const remotePath = "/" + path.relative(this._watchPath, localPath)
        const job = { localPath, remotePath, ...opts }
        this._jobQueue.push(job)
    }

    /**
     *
     * @param {} remotePath - the remote path of the file to restore. Is optional if 'localPath' is present
     * @param {} localPath - the local path of the file to restore. Is optional if 'remotePath' is present
     */
    async _rollback({ localPath, remotePath }) {
        const response = await this._db.filesListRevisions({ path: remotePath, mode: "path", limit: 10 })
        const entries = response.result.entries

        console.log(`revisions ${localPath}`)
        entries.forEach(e => console.log(`\t${e.rev}`))
        console.log("-----")

        try {
            const hash = await contentHash(localPath)

            const revisionIndex = entries.findIndex(entry => entry.content_hash === hash) // TDOO: Handle 'undefined'. Fetch more
            const revisionToRestoreTo = entries[revisionIndex + 1] // TDOO: Handle out of bounds. Fetch more
            console.log(`revision Index: ${revisionIndex}`)

            await this._db.filesRestore({ path: remotePath, rev: revisionToRestoreTo.rev })
        } catch (error) {
            if (error.errno !== -2) throw error
            await this._db.filesRestore({ path: remotePath, rev: entries[1].rev })
        }
    }

    _equivalentJobIsPending({ remotePath }) {
        const pendingJobs = [...this._jobQueue]
        return pendingJobs.some(job => job.remotePath === remotePath)
    }

    _onAdd(localPath) {
        this._debouncePushJob(localPath, { eventType: "add" })
    }

    _onChange(localPath) {
        this._debouncePushJob(localPath, { eventType: "change" })
    }

    _onUnlink(localPath) {
        this._debouncePushJob(localPath, { eventType: "unlink" })
    }

    _debouncePushJob(...args) {
        const localPath = args[0]
        if (!this.debouncers.has(localPath)) this.debouncers.set(localPath, debounce(this._pushJob.bind(this), 4000))
        const debounced = this.debouncers.get(localPath)
        debounced(...args)
    }
}

const contentHash = async localPath => {
    return new Promise((resolve, reject) => {
        //TODO: lock while hashing?
        const hasher = dch.create()
        const stream = createReadStream(localPath)
        stream.on("data", data => hasher.update(data))
        stream.on("end", () => resolve(hasher.digest("hex")))
        stream.on("error", err => reject(err))
    })
}

const macHash = async localPath => {
    //TODO: Lock while reading macs?
    const hash = createHash("sha256")
    const fd = await fsFns.open(localPath, "r")
    const size = (await fsFns.fstat(fd)).size - TOTAL_SIGNATURE_SIZE

    const chunkCount = Math.ceil(size / STREAM_CIPHER_CHUNK_SIZE) // ceil to include the last (potentially) non-full chunk
    const offset = TOTAL_SIGNATURE_SIZE + sodium.crypto_secretbox_NONCEBYTES

    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
        const start = chunkIndex * STREAM_CIPHER_CHUNK_SIZE + offset
        const mac = Buffer.alloc(sodium.crypto_secretbox_MACBYTES)
        await fsFns.read(fd, mac, 0, sodium.crypto_secretbox_MACBYTES, start)
        hash.update(mac)
    }

    return Buffer.from(hash.digest("hex"), "hex")
}

module.exports = IntegrityChecker
