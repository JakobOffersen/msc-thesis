const fs = require("fs/promises")
const { dirname } = require("path")

class ContentHashStore {
    constructor(storePath) {
        this.storePath = storePath
        this.hashes = undefined // (remote-path) => [content-hash]. Newest content hash is the last entry
    }

    /**
     * Adds `hash` to the list of content hashes for `path`. Automatically saves to disk.
     * @param {*} path
     * @param {*} hash
     */
    async add(path, hash) {
        await this.#init()

        this.#append(path, hash)
        await this.#save()
    }

    /**
     * Returns true if the store already contains `hash` for `path`.
     * @param {*} path
     * @param {*} hash
     * @returns
     */
    async has(path, hash) {
        await this.#init()

        return this.hashes.get(path)?.includes(hash)
    }

    /**
     * Returns the newest hash for `path` or null if we don't have any.
     * @param {*} path
     * @returns
     */
    async newest(path) {
        await this.#init()

        const list = this.hashes.get(path)
        if (!list || list.length === 0) return null

        return list[list.length - 1] // return the last entry, since newer entries are appended.
    }

    async #init() {
        if (!this.hashes) {
            this.hashes = await this.#read()
        }
    }

    /**
     * Appends `hash` to the array of `path`
     * @param {*} path
     * @param {*} hash
     */
    async #append(path, hash) {
        if (!this.hashes.has(path)) this.hashes.set(path, [])

        let hashes = this.hashes.get(path)
        hashes.push(hash)
        this.hashes.set(path, hashes)
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
            await fs.writeFile(this.storePath, JSON.stringify(this.hashes, replacer, 2))
        } catch {
            // the path does not exist. create it
            const dirpath = dirname(this.storePath)
            await fs.mkdir(dirpath, { recursive: true })
            await this.#save()
        }
    }
}

function replacer(_, value) {
    if (!(value instanceof Map)) return value
    return { dataType: "Map", value: [...value] }
}

function reviver(_, value) {
    return typeof value === "object" && value !== null && value.dataType === "Map" ? new Map(value.value) : value
}

module.exports = ContentHashStore
