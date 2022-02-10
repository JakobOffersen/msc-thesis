const { basename, dirname, join } = require("path")

const {LOCAL_KEYRING_PATH } = require("./constants")

console.log(dirname(LOCAL_KEYRING_PATH))
console.log(basename(LOCAL_KEYRING_PATH))
console.log(join(dirname(LOCAL_KEYRING_PATH), "", basename(LOCAL_KEYRING_PATH)))