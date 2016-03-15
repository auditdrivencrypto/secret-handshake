var handshake = require('./handshake')
var secure = require('./secure')

exports.client =
exports.createClient = function (alice, app_key, timeout) {
  var create = handshake.client(alice, app_key, timeout)

  return function (bob, cb) {
    if(!Buffer.isBuffer(bob) || bob.length != 32)
      throw new Error('createClient *must* be passed a public key')
    return create(bob, secure(cb))
  }

}
exports.server =
exports.createServer = function (bob, authorize, app_key, timeout) {
  var create = handshake.server(bob, authorize, app_key, timeout)

  return function (cb) {
    return create(secure(cb))
  }

}


