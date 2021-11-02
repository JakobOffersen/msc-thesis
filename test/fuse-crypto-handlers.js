const assert = require('chai').assert
const handlers = require('../fuse-crypto-handlers')
const path = require('path').join(__dirname, "/tmp/write-read-file.txt")
const fs = require('fs')
const crypto = require('../crypto')

describe("fuse-crypto-handlers.js", function() {
    beforeEach('setup test-file', function(done) {
        // this also overwrites the (potentially) existing test-file
        fs.open(path, 'w+', (err, _) => {
            done(err) // fails if err is truthy
        })
    })

    afterEach('teardown test-file', function(done) {
        fs.rm(path, (err) => {
            done(err) // fails if err is truthy
        })
    })

    it("writing small file and then reading same file", function(done) {
        const content = Buffer.from("hello world")
        handlers.write(path, "fd", content, content.length, 0, (length) => {
            assert.isTrue(length === content.length)

            const readBuffer = Buffer.alloc(content.length)

            handlers.read(path, "fd", readBuffer, content.length, 0, (length) => {
                assert.isTrue(length === content.length)
                assert.isTrue(Buffer.compare(content, readBuffer) === 0)
                done()
            })
        })
    })

    it('Writing file encrypts it', function(done) {
        const content = Buffer.from("hello world")

        handlers.write(path, "fd", content, content.length, 0, (length) => {
            assert.isTrue(length === content.length)

            // compare 'content' with what was written to 'path'
            fs.readFile(path, (err, data) => {
                if (err) return done(err)
                assert.isFalse(Buffer.compare(content, data) === 0) // '.compare' returns 0 when the two buffers are equal
                assert.isFalse(Buffer.compare(content, data.slice(crypto.NONCE_LENGTH)) === 0) // verify that the bytes after the nonce are differnet from 'content
                done()
            })
        })
    })

    it('Appending to existing file and then reading it', function(done) {
        const content1 = Buffer.from("hello world")
        const content2 = Buffer.from("many times!")
        const combined = Buffer.concat([content1, content2])

        handlers.write(path, "fd", content1, content1.length, 0, (length) => {
            assert.isTrue(length === content1.length)

            const endOfFirstWrite = content1.length
            handlers.write(path, "fd", content2, content2.length, endOfFirstWrite, (length) => {
                assert.isTrue(length === content2.length)

                const readBuffer = Buffer.alloc(content1.length + content2.length)
                handlers.read(path, "fd", readBuffer, readBuffer.length, 0, (length) => {
                    assert.isTrue(readBuffer.length === length)

                    assert.isTrue(Buffer.compare(combined, readBuffer) === 0) // .compare returns 0 when the two buffers are equal
                    done()
                })
            })
        })
    })
})