const IntegrityChecker = require("../integrity-checker")
const { DropboxProvider } = require("../storage_providers/storage_provider")
const { beforeShutdown } = require("../util")
const { DateTime } = require("luxon")
const KeyRing = require("../keyring")
const crypto = require("../crypto")
const { join } = require("path")

//TODO: Træk dropbox-client-path og accessToken ud i .env/config-fil
const accessToken = "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"
const dropboxClientPath = "/Users/jakoboffersen/Dropbox"
const fsp = new DropboxProvider(accessToken, __dirname)

// NOTE: This daemon currently only verifies signatures using the key-ring below.
// The keyring is populated with a verify-key in the bottom of this file.
// This is for demonstration purposes only, and should likely be extended
// to a more sophisticated setup at a later stage.
const kr = new KeyRing(join(__dirname, "mock.keyring"))
const testfilename = join(__dirname, "test-file.txt")

const verifySignature = async (content) => {
	const keytype = "buffer"
	const verifyCapability = await kr.getCapabilityWithPathAndType(testfilename, "verify", keytype)
	if (verifyCapability === null) return true // allow changes to files for which we don't have the key
	try {
		const { verified } = crypto.verifyCombined(content, verifyCapability.key)
		return verified
	} catch {
        // format error. Could be if a short file has no signature at all.
        return false
    }
}

const checker = new IntegrityChecker({
	fsp,
	watchPath: dropboxClientPath,
	predicate: verifySignature,
})

checker.on(IntegrityChecker.READY, () => {
	console.log(timestamp("ready"))
})

checker.on(IntegrityChecker.CONFLICT_FOUND, ({ remotePath, eventType, id }) => {
	console.log(timestamp(`${id}. conflict found. ${eventType} ; ${remotePath}`))
})

checker.on(IntegrityChecker.NO_CONFLICT, ({ remotePath, eventType, id }) => {
	console.log(timestamp(`${id}. No conflict. ${eventType} ; ${remotePath}`))
})

checker.on(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, ({ remotePath, eventType, id }) => {
	console.log(timestamp(`${id}. conflict resolution succeeded. ${eventType} ; ${remotePath}`))
})

checker.on(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, ({ remotePath, error, eventType, id }) => {
	console.error(timestamp(`${id}. conflict resolution failed. ${eventType} ; ${error} ; ${remotePath}`))
})

checker.on(IntegrityChecker.CHANGE, ({ remotePath, eventType, id }) => {
	console.log(timestamp(`${id}. detected change. ${eventType} ; ${remotePath}`))
})

beforeShutdown(() => {
	console.log(timestamp(`shutdown integrity-daemon`))
})

function timestamp(msg) {
	const format = { ...DateTime.TIME_24_WITH_SECONDS, ...DateTime.DATE_SHORT }
	return `[${DateTime.now().toLocaleString(format)}] ${msg}`
}

;(async () => {
	await kr.addCapability({
		type: "verify",
		key: "54cebd9c7462d6aab282f8cb2b57feef9cc5082450cfb36f76117cefa84143da",
		path: testfilename,
	})

	console.log(timestamp(`start integrity-daemon`))
})()
