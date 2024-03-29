const { Dropbox } = require("dropbox")
const { LOCAL_KEYRING_PATH, FSP_ACCESS_TOKEN, LOCAL_USERPAIR_PATH } = require("../constants.js")
const Keyring = require("../key-management/keyring.js")
const { encryptAsymmetric } = require("../utilities/crypto.js")
const { join, dirname, basename } = require("path")
const { v4: uuidv4 } = require("uuid")

const args = process.argv.slice(2)
const dbx = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })

async function share(path, sender, recipient, capabilityTypes) {
    if (!Buffer.isBuffer(recipient)) recipient = Buffer.from(recipient, "hex")
    sender = sender || ""

    const keyringPath = join(dirname(LOCAL_KEYRING_PATH), sender, basename(LOCAL_KEYRING_PATH))
    const userpairPath = join(dirname(LOCAL_USERPAIR_PATH), sender, basename(LOCAL_USERPAIR_PATH))
    const keyring = new Keyring(keyringPath, userpairPath)

    const capabilities = await Promise.all(capabilityTypes.map(type => keyring.getCapabilityWithPathAndType(path, type, "string")))

    const cipher = encryptAsymmetric(JSON.stringify(capabilities), recipient)

    const filename = uuidv4()
    const recipientPostalBox = join("/users", recipient.toString("hex"))
    const filepath = join(recipientPostalBox, filename + ".txt")

    await dbx.filesUpload({ path: filepath, mode: "overwrite", contents: cipher })
}

const [path, sender, recipient, ...capabilityTypes] = args

share(path, sender, recipient, capabilityTypes).then(() => {
    console.log(`shared ${capabilityTypes} for ${path} with user ${recipient}`)
})