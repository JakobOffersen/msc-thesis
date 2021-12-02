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
    async downloadRevision(revisionID) { abstract() }
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

        // wrap in try-catch-finally to ensure 'file' is closes before returning
        try {
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
        } catch (error) {
            throw error
        } finally {
            await file.close()
        }
    }

    async downloadRevision(revisionID) {
        const response = await this.client.filesDownload( { path: "rev:" + revisionID })
        return response.result.fileBinary
    }

    async downloadFile(relativeFilePath, { shouldWriteToDisk = true }) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeFilePath)

        const response = await this.client.filesDownload({ path: fullPathRemote })
        const result = response.result

        if (shouldWriteToDisk) {
            var file;
            // wrap file handling in try/catch/finally to ensure filehandle is closed properly
            try {
                const fullPathLocal = path.join(this.baseDirLocal, relativeFilePath)
                const file = await fs.open(fullPathLocal, "w+")
                await fs.writeFile(file, result.fileBinary, "binary")
            } catch (error) {
                throw error
            } finally {
                if (!!file) file.close()
            }
        }

        return result
    }

    async delete(relativePath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativePath)
        return await this.client.filesDeleteV2({ path: fullPathRemote })
    }

    async createDirectory(relativeDirectoryPath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeDirectoryPath)
        return await this.client.filesCreateFolderV2({ path: fullPathRemote })
    }

    async deleteDirectory(relativeDirectoryPath) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeDirectoryPath)
        return await this.client.filesDeleteV2({ path: fullPathRemote })
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
        const response = await this.client.filesListRevisions({ path: fullPathRemote, mode: "path", limit: 100 })
        return response.result
    }

    async restoreFile(relativeFilePath, revisionID ) {
        const fullPathRemote = path.join(this.baseDirRemote, relativeFilePath)
        return await this.client.filesRestore( { path: fullPathRemote, rev: revisionID })
    }
}

module.exports = {
    DropboxProvider, StorageProvider
}