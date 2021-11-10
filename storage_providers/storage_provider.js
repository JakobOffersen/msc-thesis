const fs = require("fs/promises")
const path = require("path")
const { Dropbox } = require("dropbox")

const abstract = () => { throw new Error("This method must be implemented by a subclass") }

class StorageProvider {
    constructor() {
        if (new.target === StorageProvider) {
            throw new TypeError("Only subclasses of StorageProvider can be constructed")
        }
    }

    /* File operations */

    async upload(filePath) { abstract() }
    async download(filePath) { abstract() }
    async delete(filePath) { abstract() }
    async createDirectory(directoryPath) { abstract() }
    async deleteDirectory(directoryPath) { abstract() }
    async longpoll(directoryPath) { abstract() }

}

class DropboxProvider extends StorageProvider {

    MAX_UPLOAD_TRANSFER_SIZE = 150 * (1024 ** 2) // 150 MB
    MAX_FILE_SIZE = 350 * (1024 ** 3) // 350 GB
    MIN_LONG_POLL_TIMEOUT = 30 // 30 seconds
    MAX_LONG_POLL_TIMEOUT = 480 // 8 minutes

    constructor(accessToken, baseDir) {
        super()
        this.client = new Dropbox({ accessToken: accessToken })
        this.baseDir = baseDir
    }

    async upload(filePath) {
        const fullPath = path.join(this.baseDir, filePath)
        const file = await fs.open(fullPath, "r")
        const stat = await fs.stat(fullPath)

        if (stat.size > this.MAX_FILE_SIZE) {
            throw new Error("File exceeds maximum size")
        }

        if (stat.size < this.MAX_UPLOAD_TRANSFER_SIZE) {
            const contents = await file.readFile()
            await this.client.filesUpload({ path: filePath, mode: "overwrite", contents })
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
                        commit: { path: filePath, mode: "overwrite" }
                    })

                    offset += remaining

                    break
                }
            }
        }

        await file.close()

    }

    async download(filePath) {
        const fullPath = path.join(this.baseDir, filePath)
        const file = await fs.open(fullPath, "r+")
        const response = await this.client.filesDownload({ path: filePath })
        const result = response.result

        await fs.writeFile(file, result.fileBinary, "binary")
        console.log(`File: ${result.name} saved as ${path}.`)
    }

    async delete(filePath) {
        return this.client.filesDeleteV2({ path: filePath })
    }

    async createDirectory(filePath) {
        return this.client.filesCreateFolderV2({ path: filePath })
    }

    async deleteDirectory(directoryPath) {
        return this.client.filesDeleteV2({ path: directoryPath })
    }

    async longpoll(directoryPath) {
        // https://www.dropbox.com/developers/documentation/http/documentation#files-list_folder
        const fullPath = path.join(this.baseDir, directoryPath)

        const latestCursorResponse = await this.client.filesListFolderGetLatestCursor({ path : fullPath })
        const latestCursor = latestCursorResponse.result.cursor
        console.log("latest cursor", latestCursor)
        return this.client.filesListFolderLongpoll({ cursor: latestCursor, timeout: this.MIN_LONG_POLL_TIMEOUT })
    }

    async

}

module.exports = {
    DropboxProvider
}