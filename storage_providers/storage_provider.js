const fs = require("fs/promises")
const path = require("path")
const { Dropbox } = require("dropbox")
const EventEmitter = require('events')

const abstract = () => { throw new Error("This method must be implemented by a subclass") }

class StorageProvider extends EventEmitter {
    constructor() {
        super()
        if (new.target === StorageProvider) {
            throw new TypeError("Only subclasses of StorageProvider can be constructed")
        }
    }

    /* File operations */

    async upload(filePath) { abstract() }
    async downloadFile(filePath) { abstract() }
    async delete(filePath) { abstract() }
    async createDirectory(directoryPath) { abstract() }
    async deleteDirectory(directoryPath) { abstract() }
    async startLongpoll(directoryPath) { abstract() }
    async stopLongpoll() { abstract() }
    async rollbackDelete(filePath) { abstract() }
    async listRevisions(filePath) { abstract() }
    async rollbackToLatestRevisionWhere(relativeFilePath, precondition) { abstract() }
}

class DropboxProvider extends StorageProvider {

    MAX_UPLOAD_TRANSFER_SIZE = 150 * (1024 ** 2) // 150 MB
    MAX_FILE_SIZE = 350 * (1024 ** 3) // 350 GB
    MIN_LONG_POLL_TIMEOUT = 30 // 30 seconds
    MAX_LONG_POLL_TIMEOUT = 480 // 8 minutes

    // Emit Event Names
    LONGPOLL_RESPONSE_RECEIVED = "longpoll-response-received"
    LONGPOLL_ERROR = "longpoll-error"
    LONGPOLL_NEW_ENTRIES = "longpoll-new-entries"

    constructor(accessToken, baseDirLocal) {
        super()
        this.client = new Dropbox({ accessToken: accessToken })
        this.baseDirLocal = baseDirLocal
        this.baseDirRemote = "/"
        this.on(this.LONGPOLL_RESPONSE_RECEIVED, this._longpollResponseListener.bind(this))
        this.on(this.LONGPOLL_ERROR, this._longpollErrorListener.bind(this))
        this._shouldStopLongpoll = true
    }

    async _longpollResponseListener({ path, cursor, response }) {
        const result = response.result
        // Setup a new longpoll. Delay the polling with 'backoff' if asked to do so by FSP
        if (result.backoff) {
            setTimeout(this.startLongpoll(path), result.backoff)
        } else {
            this.startLongpoll(path)
        }

        if (result.changes) {
            // fetch change
            try {
                const response = await this.client.filesListFolderContinue({ cursor })
                const entries = response.result.entries
                this.emit(this.LONGPOLL_NEW_ENTRIES, { path, entries })
            } catch(errer) {
                this.emit(this.LONGPOLL_ERROR, { path, error })
            }
        }
    }

    _longpollErrorListener({ path, error }) {
        console.log("_longpollErrorListener", path, error) // TODO: handle properly
    }

    async upload(relativeFilePath) {
        const fullPathLocal = path.join(this.baseDirLocal, relativeFilePath)
        const fullPathRemote = path.join(this.baseDirRemote, relativeFilePath)
        const file = await fs.open(fullPathLocal, "r")
        const stat = await fs.stat(fullPathLocal)

        if (stat.size === 0) {
            throw new Error("Empty file cannot be uploaded")
        }

        if (stat.size > this.MAX_FILE_SIZE) {
            throw new Error("File exceeds maximum size")
        }

        if (stat.size < this.MAX_UPLOAD_TRANSFER_SIZE) {
            const contents = await file.readFile()
            await this.client.filesUpload({ path: fullPathRemote, mode: "overwrite", contents })
        } else {
            const CHUNK_SIZE = 8 * (1024 ** 2) // 8 MB
            let window = Buffer.alloc(CHUNK_SIZE)
            let offset = 0

            // Create session and upload the first chunk
            await file.read(window, 0, CHUNK_SIZE)
            offset += CHUNK_SIZE

            const session = await this.client.filesUploadSessionStart({
                contents: window
            })

            // Upload remaining chunks
            while (true) {
                const remaining = stat.size - offset

                if (remaining > CHUNK_SIZE) {
                    await file.read(window, 0, CHUNK_SIZE)
                    await this.client.filesUploadSessionAppendV2({
                        contents: window,
                        cursor: { session_id: session.result.session_id, offset }
                    })

                    offset += CHUNK_SIZE

                } else {
                    await file.read(window, 0, remaining)

                    await this.client.filesUploadSessionFinish({
                        contents: window.subarray(0, remaining),
                        cursor: { session_id: session.result.session_id, offset },
                        commit: { path: relativeFilePath, mode: "overwrite" }
                    })

                    offset += remaining

                    break
                }
            }
        }

        await file.close()

    }

    async downloadFile(relativeFilePath) {
        const fullPathLocal = path.join(this.baseDirLocal, relativeFilePath)
        const fullPathRemote = path.join(this.baseDirRemote, relativeFilePath)

        var file
        try {
            file = await fs.open(fullPathLocal, "r+") // 'r+': Open file for reading and writing. An exception occurs if the file does not exist.
        } catch (error) {
            if (error.code === "ENOENT") file = await fs.open(fullPathLocal, "w+") // 'w+': Open file for reading and writing. The file is created (if it does not exist) or truncated (if it exists).
            else throw error
        }
        const response = await this.client.filesDownload({ path: fullPathRemote })
        const result = response.result

        await fs.writeFile(file, result.fileBinary, "binary")
    }

    async delete(relativePath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativePath)
        return await this.client.filesDeleteV2({ path: fullPathRemote })
    }

    async createDirectory(relativeDirectoryPath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeDirectoryPath)
        return this.client.filesCreateFolderV2({ path: fullPathRemote })
    }

    async deleteDirectory(relativeDirectoryPath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeDirectoryPath)
        return this.client.filesDeleteV2({ path: fullPathRemote })
    }

    async _getLatestFolderCursor(relativeDirectoryPath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeDirectoryPath)
        const latestCursorResponse = await this.client.filesListFolderGetLatestCursor({ path : fullPathRemote })
        return latestCursorResponse.result.cursor
    }

    async startLongpoll(relativeDirectoryPath) {
        this._shouldStopLongpoll = false
        try {
            const cursor = await this._getLatestFolderCursor(relativeDirectoryPath)
            this._longpollHandler = this.client.filesListFolderLongpoll({ cursor: cursor, timeout: this.MIN_LONG_POLL_TIMEOUT })
            .then((response) => {
                if (this._shouldStopLongpoll) return
                this.emit(this.LONGPOLL_RESPONSE_RECEIVED, {
                    path: relativeDirectoryPath,
                    cursor: cursor,
                    response: response
                })
            })
            .catch((error) => {
                if (this._shouldStopLongpoll) return
                this.emit(this.LONGPOLL_ERROR, {
                    path: relativeDirectoryPath,
                    error: error
                })
            })
        } catch (error) {
            if (this._shouldStopLongpoll) return
            this.emit(this.LONGPOLL_ERROR, {
                path: relativeDirectoryPath,
                error: error
            })
        }
    }

    stopLongpoll() {
        this._shouldStopLongpoll = true
    }

    async rollbackDelete(relativeFilePath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeFilePath)
        const { is_deleted, entries } = await this.listRevisions(relativeFilePath) // From doc: "Only revisions that are not deleted will show up [in 'entries']."

        if (!is_deleted) return

        const latestNonDeletedEntry = entries[0]

        await this.client.filesRestore( { path: fullPathRemote, rev: latestNonDeletedEntry.rev })
    }

    async listRevisions(relativeFilePath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeFilePath)
        const response = await this.client.filesListRevisions({ path: fullPathRemote, mode: "path" })
        return response.result
    }

    async rollbackToLatestRevisionWhere(relativeFilePath, precondition) {
        const { entries } = await this.listRevisions(relativeFilePath)

        // enumerate back through revisions until 'until' is met
        for (const entry of entries) {
            const response = await this.client.filesDownload( { path: "rev:" + entry.rev })
            const fileBinary = response.result.fileBinary

            // Restore the file when precondition 'until' is met
            if (precondition(fileBinary)) {
                const fullPathRemote = path.join(this.baseDirRemote, relativeFilePath)
                await this.client.filesRestore( { path: fullPathRemote, rev: entry.rev })
                return
            }
        }
        //TODO: Maybe request more revisions if none of the first 10 (default limit for .listRevisions) satisfy 'precondition'?
        throw new Error("None of the " + entries.length + " entries matched the received precondition")
    }
}

module.exports = {
    DropboxProvider
}