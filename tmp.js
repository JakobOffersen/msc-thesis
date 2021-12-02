const crypto = require("./crypto")
const { DropboxProvider } = require("./storage_providers/storage_provider")
const fs = require("fs/promises")
const { DateTime } = require("luxon")
const { relative, join } = require("path")

const accessToken = "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"
const fsp = new DropboxProvider(accessToken, __dirname)

const writeKey = Buffer.from("ac9b2962b6f65a43140032fc134ab1860345a9f0c224d340cd035f200945d58f54cebd9c7462d6aab282f8cb2b57feef9cc5082450cfb36f76117cefa84143da", "hex")
const verifyKey = Buffer.from("54cebd9c7462d6aab282f8cb2b57feef9cc5082450cfb36f76117cefa84143da", "hex")
const filename = join(__dirname, "daemons", "test-file.txt")
const filecontent = "this is a signed message"

function timestamp(msg) {
	const format = { ...DateTime.TIME_24_WITH_SECONDS, ...DateTime.DATE_SHORT }
	return `[${DateTime.now().toLocaleString(format)}] ${msg}`
}

const uploadValidFile = async () => {
	const timestamped = timestamp(filecontent)

	const signedMessage = crypto.signCombined(Buffer.from(timestamped), writeKey)
	await fs.writeFile(filename, signedMessage)

	await fsp.upload(relative(__dirname, filename))
}

const downloadAndVerify = async () => {
	const content = await fsp.downloadFile(relative(__dirname, filename), { shouldWriteToDisk: false })
    const res = crypto.verifyCombined(content.fileBinary, verifyKey)
    console.log(res)
}

const uploadInvalidFile = async () => {
    const timestamped = timestamp("this is INVALID!")
    await fs.writeFile(filename, Buffer.from(timestamped))
    await fsp.upload(relative(__dirname, filename))
}

;(async () => {
	await uploadInvalidFile()
})()
