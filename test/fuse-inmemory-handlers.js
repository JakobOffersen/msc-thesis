const assert = require('chai').assert
const handlers = require('../fuse-inmemory-handlers')

describe("fuse-inmemory-handlers.js", function() {
    it("writing file and then reading file", function() {
        const content = Buffer.from("hello world")
        const path = "f/filename.txt"
        handlers.write(path, "fd", content, content.length, 0, (length) => {
            assert.isTrue(length === content.length)

            const readBuffer = Buffer.alloc(content.length)

            handlers.read(path, "fd", readBuffer, content.length, 0, (length) => {
                assert.isTrue(length === content.length)
                assert.isTrue(Buffer.compare(content, readBuffer) === 0)
            })
        })
    })
})