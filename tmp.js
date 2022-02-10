const { join, basename, dirname } = require("path")
const fs = require("fs/promises")
const KeyRing = require("./key-management/keyring")
const { LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH } = require("./constants")
const crypto = require("./crypto")

const path = "/Users/jakoboffersen/Dropbox/users/fc467f399e9340646e8f599420f0630eb81bd1ee7d5c5df98202612c79eee10e/78f07f41-a7cc-473b-8c40-f1d69bd69a27.txt"
const keyring = new KeyRing(LOCAL_KEYRING_PATH, LOCAL_USERPAIR_PATH)

;(async () => {
    const { sk, pk } = await keyring.getUserKeyPair()
    const content = await fs.readFile(path)
    const decrypted = crypto.decryptWithPublicKey(content, pk, sk)
    console.log(decrypted.toString())
})()
