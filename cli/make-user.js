const { join, dirname, basename } = require("path")
const { Dropbox } = require("dropbox")
const Keyring = require("../key-management/keyring")
const { LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH, FSP_ACCESS_TOKEN } = require("../constants")

const args = process.argv.slice(2)
const username = args[0] || ""
const keyringPath = join(dirname(LOCAL_KEYRING_PATH), username, basename(LOCAL_KEYRING_PATH))
const userpairPath = join(dirname(LOCAL_USERPAIR_PATH), username, basename(LOCAL_USERPAIR_PATH))
const keyring = new Keyring(keyringPath, userpairPath)

const db = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })

async function main(keyring) {
    if (await keyring.hasUserKeyPair()) return

    const { pk } = await keyring.makeUserKeyPair()
    const postalBox = join("/users", pk.toString("hex"))
    await db.filesCreateFolderV2({ path: postalBox })
    console.log(`created postal box for user ${pk.toString("hex")}`)
}

;(async () => await main(keyring))()