const { LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH } = require("../constants")
const { join, dirname, basename } = require("path")
const Keyring = require("../key-management/keyring")
const { makeUser } = require("../make-user")

const args = process.argv.slice(2)
const username = args[0] || ""
const keyringPath = join(dirname(LOCAL_KEYRING_PATH), username, basename(LOCAL_KEYRING_PATH))
const userpairPath = join(dirname(LOCAL_USERPAIR_PATH), username, basename(LOCAL_USERPAIR_PATH))
const keyring = new Keyring(keyringPath, userpairPath)
makeUser(keyring).then(() => console.log("done"))
