const IntegrityChecker = require("./integrity-checker")
const { beforeShutdown } = require("../util")
const { DateTime } = require("luxon")
const KeyRing = require("../key-management/keyring")
const { LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH, BASE_DIR } = require("../constants")
const { join, dirname, basename } = require("path")

const args = process.argv.slice(2)
const username = args[0] || ""
const keyringPath = join(dirname(LOCAL_KEYRING_PATH), username, basename(LOCAL_KEYRING_PATH))
const userpairPath = join(dirname(LOCAL_USERPAIR_PATH), username, basename(LOCAL_USERPAIR_PATH))
const keyring = new KeyRing(keyringPath, userpairPath)

;(async () => {
    if (!(await keyring.hasUserKeyPair())) {
        console.log(`keyring for ${username} is not properly initialised`)
        process.exit(-1)
    }

    const { pk } = await keyring.getUserKeyPair()
    const checker = new IntegrityChecker({
        watchPath: BASE_DIR,
        keyring: keyring,
        username: pk.toString("hex")
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
        console.error(timestamp(`${remotePath}: conflict resolution failed. Error: ${JSON.stringify(error, null, 4)}`))
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
})()

function timestamp(msg) {
    const format = { ...DateTime.TIME_24_WITH_SECONDS, ...DateTime.DATE_SHORT }
    return `[${DateTime.now().toLocaleString(format)}] ${msg}`
}
