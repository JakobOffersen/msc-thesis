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

	async _onAdd(p) {
		console.log("ON ADD", p)
		await this.x(p)
	}

    async x(p) {
        const content = await fs.readFile(p)

		const satisfied = this._predicate(content)

		// Start rollback if the file does not satisfy the predicate
		if (!satisfied) {
			const relativePath = path.relative(this._watchPath, p)
			this.emit("began", relativePath)
			try {
				await this._fsp.rollbackToLatestRevisionWhere(
					relativePath,
					this._predicate
				)
				this.emit("succeeded", { relativePath })
			} catch (error) {
				this.emit("failed", { relativePath, error })
				throw error
			}
		}
    }

	async _onChange(p) {
		console.log("ON CHANGE", p)
        await this.x(p)
	}
}

module.exports = Rolbacker
