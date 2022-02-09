const crypto = require("../crypto")
const { Dropbox } = require("dropbox")
const { FSP_ACCESS_TOKEN, LOCAL_KEYRING_PATH, BASE_DIR, LOCAL_USERPAIR_PATH } = require("../constants")
const Keyring = require("../key-management/keyring")
const { join } = require("path")

const db = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })
const keyring = new Keyring(LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH)

;(async () => {
    await keyring.makeUserKeyPair()
    const pk = (await keyring.getUserPublicKey()).toString("hex")
    console.log(pk)

    const postalbox = join("/users", pk)
    await db.filesCreateFolderV2({ path: postalbox })
    console.log(`created postal box ${postalbox}`)
})()
