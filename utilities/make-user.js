const { join } = require("path")
const fs = require("fs/promises")
const { BASE_DIR, POSTAL_BOX } = require("../constants")

async function makeUser(keyring) {
    if (await keyring.hasUserKeyPair()) return
    const { pk } = await keyring.makeUserKeyPair()
    const postalBox = join(BASE_DIR, POSTAL_BOX, pk.toString("hex"))
    await fs.mkdir(postalBox, { recursive: true })
}

module.exports = makeUser
