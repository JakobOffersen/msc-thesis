const sodium = require("sodium-native")
const { join, resolve } = require("path")
// The maximum size of a message appended to the stream
// Every chunk, except for the last, in the stream is of this size.
const STREAM_CHUNK_SIZE = 4096
const STREAM_CIPHER_CHUNK_SIZE = STREAM_CHUNK_SIZE + sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES

const SIGNATURE_SIZE = sodium.crypto_sign_BYTES
const SIGNATURE_MARK = Buffer.from("signature:")
const TOTAL_SIGNATURE_SIZE = SIGNATURE_SIZE + SIGNATURE_MARK.length

const CAPABILITY_TYPE_READ = "read"
const CAPABILITY_TYPE_WRITE = "write"
const CAPABILITY_TYPE_VERIFY = "verify"

const LOCAL_KEYRING_PATH = join(__dirname, "key-management", "local.keyring")
const BASE_DIR_DROPBOX = "/Users/jakoboffersen/Dropbox"
const BASE_DIR_LOCAL = resolve("./fsp")
const MOUNT_DIR = resolve("./mnt")

const FSP_ACCESS_TOKEN = "rxnh5lxxqU8AAAAAAAAAATBaiYe1b-uzEIe4KlOijCQD-Faam2Bx5ykV6XldV86W"

module.exports = {
    STREAM_CHUNK_SIZE,
    STREAM_CIPHER_CHUNK_SIZE,
    SIGNATURE_SIZE,
    SIGNATURE_MARK,
    TOTAL_SIGNATURE_SIZE,
    CAPABILITY_TYPE_READ,
    CAPABILITY_TYPE_WRITE,
    CAPABILITY_TYPE_VERIFY,
    LOCAL_KEYRING_PATH,
    BASE_DIR_DROPBOX,
    BASE_DIR_LOCAL,
    MOUNT_DIR,
    FSP_ACCESS_TOKEN
}
