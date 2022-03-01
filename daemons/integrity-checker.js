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
const { verifyDetached, decryptAsymmetric, Hasher } = require("../crypto")
const { STREAM_CIPHER_CHUNK_SIZE, SIGNATURE_SIZE, FSP_ACCESS_TOKEN, DAEMON_CONTENT_HASH_STORE_PATH, POSTAL_BOX_SHARED } = require("../constants")
const debounce = require("debounce")
const ContentHashStore = require("./content-hash-store")
const { sleep } = require("../util.js")

/// IntegrityChecker reacts to changes on 'watchPath' (intended to be the FSP directory)
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
    static ADD_CAPABILITY = "add-capability"
    static ADD_CAPABILITY_FAILED = "add-capability-failed"

    constructor({ watchPath, keyring, username }) {
        super()
        this._dbx = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })
        this._watchPath = watchPath
        this._keyring = keyring
        this._username = username
        this._hashStore = new ContentHashStore(DAEMON_CONTENT_HASH_STORE_PATH) // (remote-path) => [valid content hashes]

        // setup watcher
        this._watcher = chokidar.watch(watchPath, {
            ignored: function (path) {
                return (
                    path.match(/(^|[\/\\])\../) || // ignore dot-files and ephemeral files creates by the system
                    basename(dirname(path)).split(".").length > 2 || // eg "file3.txt.sb-ab52335b-BlLaP1/file3.txt"
                    (basename(path).split(".").length > 2 && extname(path) !== ".deleted") || // eg "/milky-way-nasa.jpg.sb-ab52335b-jqZvPa/milky-way-nasa.jpg.sb-ab52335b-j7X3TY"
                    (path.includes("/users/") && !(path.includes("/users/" + this._username) || path.includes(POSTAL_BOX_SHARED))) // ignore all postal boxes except for your own postal box and the shared postal box
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
            if (this._equivalentJobIsPending(job)) return this.emit(IntegrityChecker.EQUIVALENT_CONFLICT_IS_PENDING, job)

            const { localPath, remotePath, eventType } = job
            const verified = await this._verify(job)

            // check if the content hash has been seen before. If it has, we conclude that the file has
            // been restored to an older revision, which is not allowed. In that case we re-store to the
            // newest valid version of the file
            if (verified) {
                const path = eventType === "unlink" ? localPath + ".deleted" : localPath
                const contentHash = await dropboxContentHash(path)
                const seenBefore = await this._hashStore.has(remotePath, contentHash)
                const newest = await this._hashStore.newest(remotePath)

                if (seenBefore && newest !== contentHash) {
                    this.emit(IntegrityChecker.CONFLICT_FOUND, job)

                    await this._restore({ remotePath, contentHash: newest })

                    this.emit(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, job)
                } else {
                    await this._hashStore.add(remotePath, contentHash)
                    return this.emit(IntegrityChecker.NO_CONFLICT, job)
                }
            } else {
                this.emit(IntegrityChecker.CONFLICT_FOUND, job)

                const newest = await this._hashStore.newest(remotePath)
                await this._restore({ remotePath, contentHash: newest })

                this.emit(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, job)
            }
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
        if (extname(localPath) === ".deleted" && eventType === "unlink") return false // we dont allow .deleted files to be deleted

        const verifyCapability = await this._keyring.getCapabilityWithPathAndType(remotePath, "verify")
        if (!verifyCapability) return true // we accept files we cannot check.

        try {
            if (eventType === "unlink") {
                // step 1)
                // A valid delete follows the schema:
                //      <signature(remote-path)>
                // Thus we accept the file-delete iff
                // 1) the signature is present
                // 2) the signed message is the remote path of the file

                const deleteMarkerLocalPath = localPath + ".deleted"
                const signature = await fs.readFile(deleteMarkerLocalPath)
                const verified = verifyDetached(signature, Buffer.from(remotePath), verifyCapability.key)

                if (!verified) return false // the signature is not valid. No need to check further
            } else {
                // is a regular write-operation: verify the signature
                // compute the hash of the content
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
            }

            throw error
        }
    }

    /** Checks if the modified file at 'localPath' satisfies the predicate given in the constructor
     *  If not, the file at 'localPath' is restored to the latest revision which satisfy 'predicate'.
     *
     * @param {string} localPath
     */
    async _pushJob({ localPath, ...opts }) {
        const remotePath = this._remotePath(localPath)
        const job = { localPath, remotePath, ...opts }
        this._jobQueue.push(job)
    }

    /// Restores to the revision having 'contentHash'
    async _restore({ remotePath, contentHash, retries = 0 } = {}) {
        if (retries === 10) throw new Error(`failed _restore ${remotePath}. Tried ${retries} times`)

        const response = await this._dbx.filesListRevisions({ path: remotePath, mode: "path", limit: 10 })

        let entries = response.result.entries

        try {
            for (const entry of entries) {
                if (entry.content_hash === contentHash) {
                    await this._dbx.filesRestore({ path: remotePath, rev: entry.rev }) // this may throw
                    return
                }
            }
            throw new Error("_restore gone wrong")
        } catch {
            await sleep(1000)
            await this._restore({ remotePath, contentHash, retries: retries + 1 })
        }
    }

    // Performance optimization: If an equivalent job is already pending,
    // then it will perform the rollback that this job requests.
    // Thus this job is reduntant and we can mark it as completed prematurely.
    // This is purely a performance optimization.
    _equivalentJobIsPending({ remotePath }) {
        const pendingJobs = [...this._jobQueue]
        return pendingJobs.some(job => job.remotePath === remotePath)
    }

    _onAdd(localPath) {
        if (localPath.includes("/users/" + this._username)) {
            this._checkOwnPostalbox(localPath)
        } else if (localPath.includes(POSTAL_BOX_SHARED)) {
            this._checkSharedPostalBox(localPath)
        } else {
            this._debouncePushJob({ localPath, eventType: "add" })
        }
    }

    _onChange(localPath) {
        if (localPath.includes("/users/" + this._username) || localPath.includes(POSTAL_BOX_SHARED)) return // ignore changes made in ones own or shared postal box
        this._debouncePushJob({ localPath, eventType: "change" })
    }

    _onUnlink(localPath) {
        if (localPath.includes("/users/" + this._username) || localPath.includes(POSTAL_BOX_SHARED)) return // ignore changes made in ones own or shared postal box
        this._debouncePushJob({ localPath, eventType: "unlink" })
    }

    _debouncePushJob({ localPath, eventType }) {
        if (!this.debouncers.has(localPath)) this.debouncers.set(localPath, debounce(this._pushJob.bind(this), 3000))
        const debounced = this.debouncers.get(localPath)
        this.emit(IntegrityChecker.CHANGE, { remotePath: this._remotePath(localPath), localPath, eventType })
        debounced({ localPath, eventType })
    }

    async _checkSharedPostalBox(localPath) {
        try {
            const content = await fs.readFile(localPath)
            const capability = JSON.parse(content)
            await this._keyring.addCapability(capability)
            this.emit(IntegrityChecker.ADD_CAPABILITY, { localPath, remotePath: this._remotePath(localPath), capability })
        } catch (error) {
            this.emit(IntegrityChecker.ADD_CAPABILITY_FAILED, { localPath, remotePath: this._remotePath(localPath), error })
        }
    }

    async _checkOwnPostalbox(localPath) {
        try {
            const { sk, pk } = await this._keyring.getUserKeyPair()
            const content = await fs.readFile(localPath)
            const decrypted = decryptAsymmetric(content, pk, sk)
            const capabilities = JSON.parse(decrypted)

            for (const capability of capabilities) {
                await this._keyring.addCapability(capability)
                this.emit(IntegrityChecker.ADD_CAPABILITY, { localPath, remotePath: this._remotePath(localPath), capability })
            }
        } catch (error) {
            this.emit(IntegrityChecker.ADD_CAPABILITY_FAILED, { localPath, remotePath: this._remotePath(localPath), error })
        }
    }

    _remotePath(localPath) {
        return "/" + relative(this._watchPath, localPath)
    }
}

// A hash of the entire file content computed in the same way that Dropbox
// computes their 'content_hash'.
async function dropboxContentHash(localPath) {
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
async function ciphertextHash(localPath) {
    //TODO: Lock while reading?
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
