var handshake = require('./handshake')
var secure = require('./secure')
var cl = require('chloride')

function isBuffer(buf, len) {
  return Buffer.isBuffer(buf) && buf.length === len
}

exports.client =
exports.createClient = function (alice, app_key, timeout) {
  var create = handshake.client(alice, app_key, timeout)

  return function (bob, seed, cb) {
    if(!isBuffer(bob, 32))
      throw new Error('createClient *must* be passed a public key')
    if('function' === typeof seed)
      return create(bob, secure(seed))
    else
      return create(bob, seed, secure(cb))
  }

}
exports.server =
exports.createServer = function (bob, authorize, app_key, timeout) {
  var create = handshake.server(bob, authorize, app_key, timeout)

  return function (cb) {
    return create(secure(cb))
  }

}



