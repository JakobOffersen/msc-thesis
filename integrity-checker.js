const chokidar = require("chokidar")
const path = require("path")
const EventEmitter = require("events")
const fs = require("fs/promises")
const queue = require("async/queue")
const { v4: uuidv4 } = require("uuid")

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

	constructor({ fsp, watchPath, predicate }) {
		super()
		this._fsp = fsp
		this._watchPath = watchPath
		this._predicate = predicate

        // We use a job-queue for the rollback-jobs.
        // Jobs are 'push'ed onto the queue and handled by a single worker.
        // The worker restores the invalid file to its latest valid state
		this._jobQueue = queue(async (job) => { // This attaches the worker
			const didPerformRollback = await this._performFileRestoreIfNecessary(job)
			if (didPerformRollback) {
				this.emit(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, job)
			} else {
				this.emit(IntegrityChecker.NO_CONFLICT, job)
			}
		})

		this._jobQueue.error((error, job) => {
			this.emit(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, { error, ...job })
		})

		// setup watcher
		this._watcher = chokidar.watch(watchPath, {
			ignored: /(^|[\/\\])\../, // ignore dotfiles
			persistent: true,
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

	_onAdd(localPath) {
		this._checkIfRollbackNeeded(localPath, { eventType: "add", id: uuidv4() })
	}

	_onChange(localPath) {
		this._checkIfRollbackNeeded(localPath, { eventType: "change", id: uuidv4() })
	}

	_onUnlink(localPath) {
		this._checkIfRollbackNeeded(localPath, { eventType: "unlink", id: uuidv4() })
	}

	/** Checks if the modified file at 'localPath' satisfies the predicate given in the constructor
	 *  If not, the file at 'localPath' is restored to the latest revision which satisfy 'predicate'.
	 *
	 * @param {string} localPath
	 */
	async _checkIfRollbackNeeded(localPath, opts) {
        const job = {
            ...opts,
            localPath,
            remotePath: path.relative(this._watchPath, localPath)
        }

		this.emit(IntegrityChecker.CHANGE, job)

		const localContent = await fs.readFile(localPath)
        const verified = await this._predicate(localContent)
		// Start rollback if the file does not satisfy the predicate
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
     * @returns {Promise<boolean>} Resolves with 'true' to indicate a rollback for successfully performed.
     * Resolves with 'false' to indicate a rollback was not necessary
     * Rejects with error if none of the revisions satisfy the predicate or if a read/write/download file occurs.
     */
	async _performFileRestoreIfNecessary({ remotePath, localPath }) {
        const pathRemote = remotePath || path.relative(this._watchPath, localPath)
        const pathLocal = localPath || path.join(this._watchPath, remotePath)
		// check if the file has been changed since the rollback was scheduled
		let localContent = await fs.readFile(pathLocal)
		if (await this._predicate(localContent)) return false // conflict already resolved by FSP-client. Mark no conflict is needed

		const { entries: revisions } = await this._fsp.listRevisions(pathRemote)

		for (const revision of revisions) {
			localContent = await fs.readFile(pathLocal)
			if (await this._predicate(localContent)) return false // conflict already resolved by FSP-client. Mark no conflict is needed

			const remoteContent = await this._fsp.downloadRevision(revision.rev)

			const verified = await this._predicate(remoteContent)

			if (verified) {
				localContent = await fs.readFile(pathLocal)
				if (await this._predicate(localContent)) {
					return false // conflict already resolved by FSP-client. Mark no conflict is needed
				} else {
					await this._fsp.restoreFile(pathRemote, revision.rev)
					return true // mark rollback performed successfylly
				}
			}
		}

		throw new Error("None of the " + revisions.length + " revisions met the predicate.")
	}
}

module.exports = IntegrityChecker
