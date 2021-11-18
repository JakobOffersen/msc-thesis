const chokidar = require("chokidar")
const path = require("path")
const { EventEmitter } = require("stream")
const fs = require("fs/promises")

class Rolbacker extends EventEmitter {
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
			this._watcher.on("add", this._onAdd.bind(this))
			this._watcher.on("change", this._onChange.bind(this))
			this.emit("ready")
		})
	}

	async stopWatching() {
		await this._watcher.close()
	}

	async _onAdd(fullLocalPath) {
		await this._checkIfRollbackNeeded(fullLocalPath)
	}

    async _onChange(fullLocalPath) {
        await this._checkIfRollbackNeeded(fullLocalPath)
	}

    async _checkIfRollbackNeeded(fullLocalPath) {
        const content = await fs.readFile(fullLocalPath)

		const satisfied = this._predicate(content)

		// Start rollback if the file does not satisfy the predicate
		if (!satisfied) {
            const relativePath = path.relative(this._watchPath, fullLocalPath)
            try {
                this.emit("began", relativePath)

                await this._rollback(fullLocalPath)

                this.emit("succeeded", { relativePath })
            } catch (error) {
                this.emit("failed", { relativePath, error })
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

    }


}

module.exports = Rolbacker
