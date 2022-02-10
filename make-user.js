const { Dropbox } = require("dropbox")
const { FSP_ACCESS_TOKEN } = require("./constants")
const { join } = require("path")

const db = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })

async function makeUser(keyring) {
    if (await keyring.hasUserKeyPair()) return

    await keyring.makeUserKeyPair()
    const { pk } = await keyring.getUserKeyPair()

    const postalbox = join("/users", pk.toString("hex"))
    await db.filesCreateFolderV2({ path: postalbox })
    console.log(`created postal box for user ${pk.toString("hex")}`)
}

module.exports = {
    makeUser
}
