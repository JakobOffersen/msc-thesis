const chokidar = require("chokidar")
const EventEmitter = require("events")
const fs = require("fs/promises")
const { createReadStream } = require("fs")
const queue = require("async/queue")
const { basename, dirname, extname, relative, join } = require("path")
const { Dropbox } = require("dropbox")
const fsFns = require("../fsFns")
const dch = require("../dropbox-content-hasher")
const sodium = require("sodium-native")
const { verifyDetached, decryptAsymmetric, Hasher } = require("../crypto")
const {
    STREAM_CIPHER_CHUNK_SIZE,
    SIGNATURE_SIZE,
    FSP_ACCESS_TOKEN,
    POSTAL_BOX_SHARED,
    CAPABILITY_TYPE_VERIFY,
    BASE_DIR,
    DAEMON_CONTENT_REVISION_STORE_PATH
} = require("../constants")
const debounce = require("debounce")
const { retry } = require("../util.js")
const RevisionStore = require("./revision-store.js")

const dbx = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })

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

    constructor(watchPath, keyring, username) {
        super()
        this._watchPath = watchPath
        this._keyring = keyring
        this._username = username
        this._invalidRevisionsStore = new RevisionStore(DAEMON_CONTENT_REVISION_STORE_PATH)
        this.debouncers = new Map() // maps from localPath to debouce

        // setup watcher
        this._watcher = chokidar.watch(watchPath, {
            ignored: function (path) {
                path = path.trim()
                return (
                    path.match(/(^|[\/\\])\../) || // ignore dot-files and ephemeral files creates by the system
                    basename(dirname(path)).split(".").length > 2 || // eg "file3.txt.sb-ab52335b-BlLaP1/file3.txt"
                    (basename(path).split(".").length > 2 && extname(path) !== ".deleted") || // eg "/milky-way-nasa.jpg.sb-ab52335b-jqZvPa/milky-way-nasa.jpg.sb-ab52335b-j7X3TY"
                    (path.includes("/users/") && !(path.includes("/users/" + this._username) || path.includes(POSTAL_BOX_SHARED))) || // ignore all postal boxes except for your own postal box and the shared postal box
                    basename(path) === "Icon"
                )
            }.bind(this),
            persistent: true // indicates that chokidar should continue the process as long as files are watched
        })
        // Chokiar emits 'add' for all existing files in the watched directory
        // To only watch for future changes, we only add our 'add' listener after
        // the initial scan has occured.
        this._watcher.on("ready", async () => {
            this._watcher.on("add", this._onAdd.bind(this))
            this._watcher.on("change", this._onChange.bind(this))
            this._watcher.on("unlink", this._onUnlink.bind(this))
            this.emit(IntegrityChecker.READY)

            // check the shared postal box for capabilities
            try {
                const postalBoxPath = join(BASE_DIR, POSTAL_BOX_SHARED)
                const sharedPostalBoxPaths = (await fs.readdir(postalBoxPath)).map(p => join(postalBoxPath, p))

                for (const p of sharedPostalBoxPaths) {
                    await this._checkSharedPostalBox(p)
                }
            } catch {}
        })

        // We use a job-queue for the rollback-jobs.
        // Jobs are 'push'ed onto the queue and handled by a single worker.
        // The worker (the callback below) restores the invalid file to its latest valid state
        this._jobQueue = queue(async job => {
            if (this._equivalentJobIsPending(job)) return this.emit(IntegrityChecker.EQUIVALENT_CONFLICT_IS_PENDING, job)

            const { localPath, remotePath, eventType } = job
            let verified = await this._verify(job)

            if (verified && (eventType === "unlink" || extname(remotePath) === ".deleted")) {
                // We dont need to consider replay attacks for a delete-operation,
                // since they (i.e. 'file.txt' and 'file.txt.deleted') make the end of life
                // for that file.
                // => they are always required to be the newest revision for that file
                // => they cannot make a replay when they are already the newest revision
                return this.emit(IntegrityChecker.NO_CONFLICT, job)
            }

            let contentHash = undefined
            try {
                contentHash = await dropboxContentHash(localPath)
            } catch {
                // localpath has been deleted
                this.emit(IntegrityChecker.CONFLICT_FOUND, job)
                // Restore to to the newest revision
                const response = await dbx.filesListRevisions({ path: remotePath })
                const newest = response.result.entries[0]
                await retry(
                    async () => await dbx.filesRestore({ path: remotePath, rev: newest.rev }),
                    response => response.status === 200
                )
                return this.emit(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, job)
            }

            const response = await retry(
                async () => await dbx.filesListRevisions({ path: remotePath }),
                response => !!response.result.entries.find(r => r.content_hash === contentHash) // returns 'true' if a revision matches 'contentHash' else 'false'
            )

            const revs = response.result.entries
            const rxIndex = revs.findIndex(r => r.content_hash === contentHash)
            const rx = revs[rxIndex]

            if (verified) {
                // check against replay attacks
                const ryIndex = revs.findIndex(r => r.content_hash === rx.content_hash && r.rev !== rx.rev)

                if (ryIndex !== -1) {
                    // Found an earlier revision with content hash matching the current
                    const seq = revs.slice(rxIndex + 1, ryIndex) // the list of revisions inbetween the

                    for (const rz of seq) {
                        const fileContent = (await dbx.filesDownload({ path: "rev:" + rz.rev })).result.fileBinary
                        let verified = await this._verify({ localPath, remotePath, eventType, contents: fileContent })

                        if (verified) {
                            // rx may be a replay.
                            const rzIndex = revs.findIndex(r => r.rev === rz.rev)
                            const tail = revs.slice(rzIndex + 1) // the revs starting just after 'rz'
                            const rw = tail.find(r => r.content_hash === rz.content_hash)

                            if (!rw) {
                                this.emit(IntegrityChecker.CONFLICT_FOUND, job)

                                await retry(
                                    // retry restore until it succeeeds (max 10 retries)
                                    async () => await dbx.filesRestore({ path: remotePath, rev: rz.rev }),
                                    response => response.status === 200
                                )

                                return this.emit(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, job)
                            } else {
                                return this.emit(IntegrityChecker.NO_CONFLICT, job)
                            }
                        } else {
                            await this._invalidRevisionsStore.add(remotePath, rz.rev)
                        }
                    }
                }
                return this.emit(IntegrityChecker.NO_CONFLICT, job)
            } else {
                this.emit(IntegrityChecker.CONFLICT_FOUND, job)
                await this._invalidRevisionsStore.add(remotePath, rx.rev)

                const newestValidRevision = revs.slice(rxIndex + 1).find(async r => {
                    let found = await this._invalidRevisionsStore.has(remotePath, r.rev)
                    return !found
                })

                await retry(
                    // retry restore until it succeeeds (max 10 retries)
                    async () => await dbx.filesRestore({ path: remotePath, rev: newestValidRevision.rev }),
                    response => response.status === 200
                )

                this.emit(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, job)
            }
        })

        // This is called if any worker fails (e.g throws an error)
        this._jobQueue.error((error, job) => {
            console.trace()
            this.emit(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, { error, ...job })
        })
    }

    async stopWatching() {
        await this._watcher.close()
    }

    async _verify({ localPath, remotePath, eventType, contents }) {
        if (extname(localPath) === ".deleted" && eventType === "unlink") return false // we dont allow .deleted files to be deleted

        const verifyCapability = await this._keyring.getCapabilityWithPathAndType(remotePath, "verify")
        if (!verifyCapability) return true // we accept files we cannot check.

        try {
            if (eventType === "unlink" || extname(localPath) === ".deleted") {
                // step 1)
                // A valid delete follows the schema:
                //      <signature(remote-path)>
                // Thus we accept the file-delete iff
                // 1) the signature is present
                // 2) the signed message is the remote path of the file

                const localPathWithDeleteMark = extname(localPath) === ".deleted" ? localPath : localPath + ".deleted"
                const remotePathWithoutDeletedMark = extname(remotePath) === ".deleted" ? remotePath.replace(".deleted", "") : remotePath
                const signature = contents ?? (await fs.readFile(localPathWithDeleteMark))
                const verified = verifyDetached(signature, Buffer.from(remotePathWithoutDeletedMark), verifyCapability.key)

                return verified
            } else {
                // is a regular write-operation: verify the signature
                // compute the hash of the content
                if (contents) {
                    const hash = await ciphertextHashContent(contents)
                    const signature = contents.subarray(0, sodium.crypto_sign_BYTES)
                    const verified = verifyDetached(signature, hash, verifyCapability.key)
                    return verified
                } else {
                    const hash = await ciphertextHash(localPath)
                    const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
                    const fd = await fsFns.open(localPath, "r")
                    await fsFns.read(fd, signature, 0, signature.length, 0)
                    const verified = verifyDetached(signature, hash, verifyCapability.key)
                    return verified
                }
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
            // check if the keyring already contains the capability
            const existing = await this._keyring.getCapabilityWithPathAndType(capability.path, CAPABILITY_TYPE_VERIFY)
            if (!existing) {
                await this._keyring.addCapability(capability)
                this.emit(IntegrityChecker.ADD_CAPABILITY, { localPath, remotePath: this._remotePath(localPath), capability })
            }
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

async function ciphertextHashContent(contents) {
    const hasher = new Hasher()

    // Compute hash of entire file except the signature in the
    // same block size as they were written.
    const cipherSize = contents.length - SIGNATURE_SIZE
    const chunkCount = Math.ceil(cipherSize / STREAM_CIPHER_CHUNK_SIZE)
    const offset = SIGNATURE_SIZE

    let read = 0
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
        const start = chunkIndex * STREAM_CIPHER_CHUNK_SIZE + offset
        const blockSize = Math.min(STREAM_CIPHER_CHUNK_SIZE, cipherSize - read)
        const block = contents.subarray(start, start + blockSize)
        hasher.update(block)
        read += blockSize
    }

    return hasher.final()
}

// A hash of the content computed in the same way that we compute the hash in FUSE
async function ciphertextHash(localPath) {
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
