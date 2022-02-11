class FSError extends Error {
    constructor(code) {
        super()
        this.code = code
    }
}

module.exports = FSError