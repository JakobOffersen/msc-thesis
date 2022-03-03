const fs = require("fs/promises")
const { dirname } = require("path")

class RevisionStore {
    constructor(storePath) {
        this.storePath = storePath
        this.map = undefined // (remote-path) => Set<rev-ID>
    }

    /**
     * Adds `id` to the set of IDs for `path`. Automatically saves to disk.
     * @param {*} path
     * @param {*} id
     * @returns
     */
    async add(path, id) {
        await this.#init()

        if (!this.map.has(path)) this.map.set(path, new Set())
        this.map.get(path).add(id)

        this.#save()
    }

    /**
     * Returns true if the store contains revision `id` for `path`.
     * @param {*} path
     * @param {*} id
     * @returns
     */
    async has(path, id) {
        await this.#init()
        return this.map.get(path)?.has(id)
    }

    async #init() {
        if (this.map) return
        this.map = await this.#read()
    }

    async #read() {
        try {
            const content = await fs.readFile(this.storePath)
            return JSON.parse(content, reviver)
        } catch {
            // the file does not exist.
            return new Map()
        }
    }

    async #save() {
        try {
            await fs.writeFile(this.storePath, JSON.stringify(this.map ?? new Map(), replacer, 2))
        } catch {
            // the path does not exist. create it
            const dirpath = dirname(this.storePath)
            await fs.mkdir(dirpath, { recursive: true })
            await this.#save()
        }
    }
}

function replacer(_, value) {
    if (value instanceof Map) return { dataType: "Map", value: [...value] }
    if (value instanceof Set) return { dataType: "Set", value: [...value] }
    return value
}

function reviver(_, value) {
    if (typeof value === "object" && value !== null && value.dataType === "Map") return new Map(value.value)
    if (typeof value === "object" && value !== null && value.dataType === "Set") return new Set(value.value)
    return value
}

module.exports = RevisionStore
