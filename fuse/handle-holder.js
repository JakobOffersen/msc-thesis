// A helper-class for allowing file handles to be keyed by their fd *and* by their path.
class HandleHolder {
    constructor() {
        this.map = new Map() // maps from fd to FileHandle
    }

    set(key, value) {
        this.map.set(key, value)
    }

    get(key) {
        if (typeof key === "number") return this.map.get(key)

        for (const handle of this.map.values()) {
            if (handle.path === key) return handle
        }
    }

    delete(key) {
        this.map.delete(key)
    }
}

module.exports = HandleHolder