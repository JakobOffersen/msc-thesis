const { DropboxProvider } = require("../storage_providers/storage_provider")
const path = require("path")

const dropboxApp = {
    key: "b2gdry5rbkoq1jm",
    secret: "0ye07t7186lht1e",
    accessToken: "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"
}

const baseDir = path.resolve("./cache")
const provider = new DropboxProvider(dropboxApp.accessToken, baseDir);

(async () => {
    await provider.upload("/test3.bin")
})().catch(error => {
    console.error(error)
    process.exit(1)
})