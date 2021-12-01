const IntegrityChecker = require("../integrityChecker")
const { DropboxProvider } = require("../storage_providers/storage_provider")
const { beforeShutdown } = require("../util")
const { DateTime } = require("luxon")

const accessToken = "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"
const dropboxClientPath = "/Users/jakoboffersen/Dropbox"
const fsp = new DropboxProvider(accessToken, __dirname)

const predicate = (content) => {
	return Buffer.compare(content, Buffer.from("hello world")) === 0
}

const checker = new IntegrityChecker({
	fsp,
	watchPath: dropboxClientPath,
	predicate,
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

console.log(timestamp(`start integrity-daemon`))

function timestamp(msg) {
	const format = { ...DateTime.TIME_24_WITH_SECONDS, ...DateTime.DATE_SHORT }
	return `[${DateTime.now().toLocaleString(format)}] ${msg}`
}
