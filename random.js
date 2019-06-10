'use strict'
var cl = require('chloride')

module.exports = function (bytes) {
  var b = Buffer.alloc(bytes)
  cl.randombytes(b, bytes)
  return b
}
