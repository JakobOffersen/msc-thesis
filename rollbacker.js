const chokidar = require("chokidar")
const path = require("path")
const { EventEmitter } = require("stream")
const fs = require("fs/promises")

class Rolbacker extends EventEmitter {

    // EVENT NAMES
    READY = "ready"
    BEGAN = "began"
    FAILED = "failed"
    SUCCESS = "success"

	constructor({ fsp, watchPath, predicate }) {
		super()
		this._fsp = fsp
		this._watchPath = watchPath
		this._predicate = predicate

		// setup watcher
		this._watcher = chokidar.watch(watchPath, {
			ignored: /(^|[\/\\])\../, // ignore dotfiles
			persistent: true,
		})
		// Chokiar emits 'add' for all existing files in the watched directory
		// To only watch for future changes, we only add our 'add' listener after
		// the initial scan has occured.
		this._watcher.on("ready", () => {
			this._watcher.on("add", this._checkIfRollbackNeeded.bind(this))
			this._watcher.on("change", this._checkIfRollbackNeeded.bind(this))
			this.emit(this.READY)
		})
	}

	async stopWatching() {
		await this._watcher.close()
	}

    /** Checks if the modified file at 'fullLocalPath' satisfies the passed predicate
     *  If not, a rollback to the most-recent revision that satisfies the predicate is performed
     *  The outcome of the rollback is emitted ('succeeded'/'failed')
     *
     * @param {full local path to the modified file} fullLocalPath
     */
    async _checkIfRollbackNeeded(fullLocalPath) {
        const content = await fs.readFile(fullLocalPath)

		const satisfied = this._predicate(content)

		// Start rollback if the file does not satisfy the predicate
		if (!satisfied) {
            const relativePath = path.relative(this._watchPath, fullLocalPath)
            try {
                this.emit(this.BEGAN, relativePath)

                await this._rollback(fullLocalPath)

                this.emit(this.SUCCESS, { relativePath })
            } catch (error) {
                this.emit(this.FAILED, { relativePath, error })
            }
		}
    }

    async _rollback(fullLocalPath) {
        const relativePath = path.relative(this._watchPath, fullLocalPath)
        const { entries } = await this._fsp.listRevisions(relativePath)

        for (const entry of entries) {
            const content = await this._fsp.downloadRevision(entry.rev)

            const satisfied = this._predicate(content)

            if (satisfied) {
                return await this._fsp.restoreFile(relativePath, entry.rev)
            }
        }

        throw new Error("None of the " + entries.length + " revisions met the predicate.")
    }
}

module.exports = Rolbacker
