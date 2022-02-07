const { extname, dirname, basename, join } = require("path")

const fullpath = "/Users/jakoboffersen/Desktop/msc-thesis/cac-project-test/msc-thesis/test-files/1mb.txt"
const parent = dirname(fullpath)
const filename = basename(fullpath)
console.log(extname(join(parent, filename + ".deleted")))
