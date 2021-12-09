const IntegrityChecker = require("../integrity-checker")
const { DropboxProvider } = require("../storage_providers/storage_provider")
const { beforeShutdown } = require("../util")
const { DateTime } = require("luxon")
const KeyRing = require("../keyring")
const crypto = require("../crypto")
const { join } = require("path")
const { contentIsMarkedAsDeleted, verifyDeleteFileContent } = require("../file-delete-utils")

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

//TODO: How do we ensure that valid writes to already-deleted (with mark) are rejected?
const verifySignature = async ({ content, remotePath }) => {
	const verifyCapability = await kr.getCapabilityWithPathAndType(testfilename, "verify")

	if (contentIsMarkedAsDeleted(content)) {
        const latestRevisionID = await fetchLatestRevisionID(remotePath)
		const verified = verifyDeleteFileContent(content, verifyCapability.key, latestRevisionID)
		console.log(timestamp(`${remotePath}: marked as deleted. Verified: ${verified}`))
		return verified
	} else {
		// is a regular write-operation: verify the signature
		try {
			const { verified } = crypto.verifyCombined(content, verifyCapability.key) // could throw if 'content' is too short
			return verified
		} catch {
			return false
		}
	}
}

const fetchLatestRevisionID = async (remotePath) => {
	const { entries } = await fsp.listRevisions(remotePath)
	const entry = entries[1] // [0] is the revision of the file that contains 'content'. Look at the one before that
    return entry.rev
}

const checker = new IntegrityChecker({
	fsp,
	watchPath: dropboxClientPath,
	predicate: verifySignature,
})

checker.on(IntegrityChecker.READY, () => {
	console.log(timestamp("ready"))
})

checker.on(IntegrityChecker.CONFLICT_FOUND, ({ remotePath }) => {
	console.log(timestamp(`${remotePath}: conflict found.`))
})

checker.on(IntegrityChecker.NO_CONFLICT, ({ remotePath }) => {
	console.log(timestamp(`${remotePath}: No conflict.`))
})

checker.on(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, ({ remotePath }) => {
	console.log(timestamp(`${remotePath}: conflict resolution succeeded `))
})

checker.on(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, ({ remotePath, error }) => {
	console.error(timestamp(`${remotePath}: conflict resolution failed. Error: ${error}`))
})

checker.on(IntegrityChecker.CHANGE, ({ remotePath, eventType }) => {
	console.log(timestamp(`${remotePath}: detected '${eventType}'`))
})

checker.on(IntegrityChecker.EQUIVALENT_CONFLICT_IS_PENDING, ({ remotePath }) => {
	console.log(timestamp(`${remotePath}: equivalent conflict is already pending on job queue`))
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
