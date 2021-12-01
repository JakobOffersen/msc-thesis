const IntegrityChecker = require("../integrityChecker")
const { DropboxProvider } = require("../storage_providers/storage_provider")
const { beforeShutdown } = require("../util")
const { DateTime } = require("luxon")

const version = "v0.2"
const accessToken = "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"
const dropboxClientPath = "/Users/jakoboffersen/Dropbox"
const fsp = new DropboxProvider(accessToken, __dirname)

const predicate = (content, { id }) => {
    console.log(timestamp(`${id}. predicate received ${content.toString('utf-8')}`))
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

checker.on(IntegrityChecker.CONFLICT_FOUND, ({ relativePath, eventType, id }) => {
	console.log(timestamp(`${id}. conflict found. ${eventType} ; ${relativePath}`))
})

checker.on(IntegrityChecker.CONFLICT_RESOLUTION_SUCCEEDED, ({ relativePath, eventType, id }) => {
	console.log(timestamp(`${id}. conflict resolution succeeded. ${eventType} ; ${relativePath}`))
})

checker.on(IntegrityChecker.CONFLICT_RESOLUTION_FAILED, ({ relativePath, error, eventType, id }) => {
	console.error(timestamp(`${id}. conflict resolution failed. ${eventType} ; ${error} ; ${relativePath}`))
})

checker.on(IntegrityChecker.CHANGE, ({ relativePath, eventType, id }) => {
	console.log(timestamp(`${id}. detected change. ${eventType} ; ${relativePath}`))
})

beforeShutdown(() => {
	console.log(timestamp(`shutdown integrity-daemon ${version}`))
})

console.log(timestamp(`start integrity-daemon ${version}`))

function timestamp(msg) {
	const format = { ...DateTime.TIME_24_WITH_SECONDS, ...DateTime.DATE_SHORT }
	return `[${DateTime.now().toLocaleString(format)}] ${msg}`
}
