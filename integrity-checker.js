const chokidar = require("chokidar")
const path = require("path")
const EventEmitter = require("events")
const fs = require("fs/promises")
const queue = require("async/queue")
const { v4: uuidv4 } = require("uuid")
const { relative } = require("path")

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

	constructor({ fsp, watchPath, predicate }) {
		super()
		this._fsp = fsp
		this._watchPath = watchPath
		this._predicate = predicate

		// We use a job-queue for the rollback-jobs.
		// Jobs are 'push'ed onto the queue and handled by a single worker.
		// The worker (the callback below) restores the invalid file to its latest valid state
		this._jobQueue = queue(async (job) => {
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
		this._checkIfRollbackNeeded(localPath, { eventType: "add" })
	}

	_onChange(localPath) {
		this._checkIfRollbackNeeded(localPath, { eventType: "change" })
	}

	_onUnlink(localPath) {
		this._checkIfRollbackNeeded(localPath, { eventType: "unlink" })
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
			remotePath: path.relative(this._watchPath, localPath),
		}

		this.emit(IntegrityChecker.CHANGE, job)

		try {
			const localContent = await fs.readFile(localPath)
			const verified = await this._predicate({ content: localContent, remotePath: job.remotePath })

			if (verified) {
				this.emit(IntegrityChecker.NO_CONFLICT, job)
			} else {
				this.emit(IntegrityChecker.CONFLICT_FOUND, job)
				this._jobQueue.push(job)
			}
		} catch {
			// the file at 'localPath' was deleted. ALl deletes are determined to be invalid
			// since no signature verification can occur on them.
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
		return pendingJobs.some((j) => j.remotePath === job.remotePath)
	}
}

module.exports = IntegrityChecker
