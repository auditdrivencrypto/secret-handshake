var cl = require('chloride')

module.exports = function (bytes) {
  var b = new Buffer(bytes)
  cl.randombytes(b, bytes)
  return b
}
