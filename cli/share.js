const { Dropbox } = require("dropbox")
const { LOCAL_KEYRING_PATH, BASE_DIR, FSP_ACCESS_TOKEN, CAPABILITY_TYPE_READ, CAPABILITY_TYPE_VERIFY, CAPABILITY_TYPE_WRITE } = require("../constants")
const KeyRing = require("../key-management/keyring")
const { encryptWithPublicKey } = require("../crypto")
const { join } = require("path")
const { v4: uuidv4 } = require('uuid');

const args = process.argv.slice(2)
const keyring = new KeyRing(LOCAL_KEYRING_PATH)
const db = new Dropbox({ accessToken: FSP_ACCESS_TOKEN })

async function share({ path, recipient, capabilityTypes = [CAPABILITY_TYPE_READ, CAPABILITY_TYPE_VERIFY, CAPABILITY_TYPE_WRITE] } = {}) {
    if (!Buffer.isBuffer(recipient)) recipient = Buffer.from(recipient, "hex")

    const capabilities = await Promise.all(
        capabilityTypes.map(type => keyring.getCapabilityWithPathAndType(path, type))
    )

    const cipher = encryptWithPublicKey(JSON.stringify(capabilities), recipient)

    const filename = uuidv4()
    const recipientPostalBox = join("/users", recipient.toString("hex"))
    const filepath = join(recipientPostalBox, filename)

    await db.filesUpload({ path: filepath, mode: "overwrite", contents: cipher })
}

const [path, recipient, ...capabilityTypes] = args
console.log(path, recipient)
console.log(capabilityTypes)
