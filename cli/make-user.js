const { join, dirname, basename } = require("path")
const Keyring = require("../key-management/keyring.js")
const { LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH } = require("../constants.js")
const makeUser = require("../utilities/make-user.js")

const args = process.argv.slice(2)
const username = args[0] || ""
const keyringPath = join(dirname(LOCAL_KEYRING_PATH), username, basename(LOCAL_KEYRING_PATH))
const userpairPath = join(dirname(LOCAL_USERPAIR_PATH), username, basename(LOCAL_USERPAIR_PATH))
const keyring = new Keyring(keyringPath, userpairPath)

;(async () => {
    await makeUser(keyring)
    const { pk } =await keyring.getUserKeyPair()
    console.log(`created postal box for user ${pk.toString("hex")}`)
})()