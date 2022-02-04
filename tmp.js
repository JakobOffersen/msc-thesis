const { Dropbox } = require("dropbox")
const { FSP_ACCESS_TOKEN, BASE_DIR } = require("./constants")
const { join, dirname, basename, resolve } = require("path")

let path = "/milky-way-nasa.jpg.sb-ab52335b-U5cFMH"
console.log(basename(path).split(".").length > 2)
