class KeyProvider {
    constructor() {
        this._keymap = new Map()
    }

    getKeyForPath(path) {
        return Buffer.from("K/NUabfB3pz1IkThGO/oXDfzoHkUl6tQEsnl6sDi+yo=", "base64")

        let key = this._keymap.get(path)

        if (!key) {
            const key = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)
            sodium.crypto_secretstream_xchacha20poly1305_keygen(key)
            this._keymap.set(path, key)
        }

        return key
    }
}

module.exports = KeyProvider