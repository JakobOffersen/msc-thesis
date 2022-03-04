// NOTE: THIS FILE IS COPIED FROM DROPBOX'S OPEN SOURCE REPOSITORY 'dropbox-api-content-hasher'
// WE (JAKOB V. OFFERSEN, AUGUST B. HEEGAARD) HAVE MADE NO CONTRIBUTION OR EDIT TO THE FILE.
// THE FILE CAN IS PUBLICALLY AVAILABLE AT https://github.com/dropbox/dropbox-api-content-hasher/blob/master/js-node/dropbox-content-hasher.js
// LICENCE: https://github.com/dropbox/dropbox-api-content-hasher/blob/master/License.txt

"use strict"

const crypto = require("crypto")

const BLOCK_SIZE = 4 * 1024 * 1024

function DropboxContentHasher(overallHasher, blockHasher, blockPos) {
    this._overallHasher = overallHasher
    this._blockHasher = blockHasher
    this._blockPos = blockPos
}

DropboxContentHasher.prototype.update = function (data, inputEncoding) {
    if (this._overallHasher === null) {
        throw new AssertionError("can't use this object anymore; you already called digest()")
    }

    if (!Buffer.isBuffer(data)) {
        if (inputEncoding !== undefined && inputEncoding !== "utf8" && inputEncoding !== "ascii" && inputEncoding !== "latin1") {
            // The docs for the standard hashers say they only accept these three encodings.
            throw new Error("Invalid 'inputEncoding': " + JSON.stringify(inputEncoding))
        }
        data = Buffer.from(data, inputEncoding)
    }

    let offset = 0
    while (offset < data.length) {
        if (this._blockPos === BLOCK_SIZE) {
            this._overallHasher.update(this._blockHasher.digest())
            this._blockHasher = crypto.createHash("sha256")
            this._blockPos = 0
        }

        let spaceInBlock = BLOCK_SIZE - this._blockPos
        let inputPartEnd = Math.min(data.length, offset + spaceInBlock)
        let inputPartLength = inputPartEnd - offset
        this._blockHasher.update(data.slice(offset, inputPartEnd))

        this._blockPos += inputPartLength
        offset = inputPartEnd
    }
}

DropboxContentHasher.prototype.digest = function (encoding) {
    if (this._overallHasher === null) {
        throw new AssertionError("can't use this object anymore; you already called digest()")
    }

    if (this._blockPos > 0) {
        this._overallHasher.update(this._blockHasher.digest())
        this._blockHasher = null
    }
    let r = this._overallHasher.digest(encoding)
    this._overallHasher = null // Make sure we can't use this object anymore.
    return r
}

exports.BLOCK_SIZE = BLOCK_SIZE
exports.create = function () {
    return new DropboxContentHasher(crypto.createHash("sha256"), crypto.createHash("sha256"), 0)
}
