const chokidar = require("chokidar")
const path = require("path")
const EventEmitter = require("events")
const fs = require("fs/promises")
const queue = require("async/queue")
const { v4: uuidv4 } = require("uuid")

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
		this._jobQueue = queue(async (job) => {
			const didPerformRollback = await this._rollbackIfNecessary(job.relativePath, job)
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

	_onAdd(fullLocalPath) {
		this._checkIfRollbackNeeded(fullLocalPath, { eventType: "add", id: uuidv4() })
	}

	_onChange(fullLocalPath) {
		this._checkIfRollbackNeeded(fullLocalPath, { eventType: "change", id: uuidv4() })
	}

	_onUnlink(fullLocalPath) {
		this._checkIfRollbackNeeded(fullLocalPath, { eventType: "unlink", id: uuidv4() })
	}

	/** Checks if the modified file at 'fullLocalPath' satisfies the passed predicate
	 *  If not, a rollback to the most-recent revision that satisfies the predicate is performed
	 *  The outcome of the rollback is emitted ('succeeded'/'failed')
	 *
	 * @param {full local path to the modified file} fullLocalPath
	 */
	async _checkIfRollbackNeeded(fullLocalPath, opts) {
		const relativePath = path.relative(this._watchPath, fullLocalPath)

		this.emit(IntegrityChecker.CHANGE, { relativePath, ...opts })

		const verified = await this.localRevisionIsVerified(relativePath, opts)
		// Start rollback if the file does not satisfy the predicate
		if (verified) {
			this.emit(IntegrityChecker.NO_CONFLICT, { relativePath, ...opts })
		} else {
			this.emit(IntegrityChecker.CONFLICT_FOUND, { relativePath, ...opts })

			this._jobQueue.push({ relativePath, ...opts })
		}
	}

	async localRevisionIsVerified(relativePath, opts) {
		const content = await fs.readFile(path.join(this._watchPath, relativePath))
		const verified = this._predicate(content, opts)
		return verified
	}

	async _rollbackIfNecessary(relativePath, opts) {
		// check if the file has been changed since the rollback was scheduled
		if (await this.localRevisionIsVerified(relativePath, opts)) {
			return false
		}

		const { entries: revisions } = await this._fsp.listRevisions(relativePath)

		for (const revision of revisions) {
			if (await this.localRevisionIsVerified(relativePath, opts)) {
				return false
			}

			const content = await this._fsp.downloadRevision(revision.rev)

			const verified = this._predicate(content, opts)

			if (verified) {
				if (await this.localRevisionIsVerified(relativePath, opts)) {
					return false
				}
				console.log("RESTORE FILE", opts.id)
				await this._fsp.restoreFile(relativePath, revision.rev)
				return true
			}
		}

		throw new Error("None of the " + entries.length + " revisions met the predicate.")
	}
}

module.exports = IntegrityChecker
