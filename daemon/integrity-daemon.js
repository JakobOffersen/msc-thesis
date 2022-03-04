const IntegrityChecker = require("./integrity-checker.js")
const { beforeShutdown } = require("../utilities/util.js")
const { DateTime } = require("luxon")
const Keyring = require("../key-management/keyring.js")
const { LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH, BASE_DIR } = require("../constants.js")
const { join, dirname, basename } = require("path")
const makeUser = require("../utilities/make-user.js")

;(async () => {
    const args = process.argv.slice(2)
    const username = args[0] || ""
    const keyringPath = join(dirname(LOCAL_KEYRING_PATH), username, basename(LOCAL_KEYRING_PATH))
    const userpairPath = join(dirname(LOCAL_USERPAIR_PATH), username, basename(LOCAL_USERPAIR_PATH))
    const keyring = new Keyring(keyringPath, userpairPath)

    if (!(await keyring.hasUserKeyPair())) {
        await makeUser(keyring) // this creates the users key pair and postal box
    }

    let { pk } = await keyring.getUserKeyPair()
    pk = pk.toString("hex")

    const checker = new IntegrityChecker(BASE_DIR, keyring, pk)

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

    checker.on(IntegrityChecker.ADD_CAPABILITY, ({ capability }) => {
        console.log(timestamp(`add capability ${capability.type} for path ${capability.path}`))
    })

    checker.on(IntegrityChecker.ADD_CAPABILITY_FAILED, ({ remotePath, error }) => {
        console.error(timestamp(`Add capability from path ${remotePath} failed with error ${error}`))
    })

    beforeShutdown(() => {
        console.log(timestamp(`shutdown integrity-daemon`))
    })
})()

function timestamp(msg) {
    const format = { ...DateTime.TIME_24_WITH_SECONDS, ...DateTime.DATE_SHORT }
    return `[${DateTime.now().toLocaleString(format)}] ${msg}`
}
