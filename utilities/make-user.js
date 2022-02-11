const { join } = require("path")
const { Dropbox } = require("dropbox")
const { FSP_ACCESS_TOKEN } = require("../constants")
const dbx = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })

async function makeUser(keyring) {
    if (await keyring.hasUserKeyPair()) return

    const { pk } = await keyring.makeUserKeyPair()
    const postalBox = join("/users", pk.toString("hex"))
    await dbx.filesCreateFolderV2({ path: postalBox })
}

module.exports = makeUser
