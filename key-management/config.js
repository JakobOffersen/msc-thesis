const { join } = require("path")

const TYPE_READ = "read"
const TYPE_WRITE = "write"
const TYPE_VERIFY = "verify"
const LOCAL_KEYRING_PATH = join(__dirname, "local.keyring")

module.exports = {
    TYPE_READ,
    TYPE_WRITE,
    TYPE_VERIFY,
    LOCAL_KEYRING_PATH
}
