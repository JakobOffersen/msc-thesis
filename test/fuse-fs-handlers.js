const assert = require('chai').assert
const handlers = require('../fuse-fs-handlers')
const path = require('path').join(__dirname, "/tmp/write-read-file.txt")
const fs = require('fs')

describe("fuse-fs-handlers.js", function() {
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
})