var handshake = require('./handshake')
var secure = require('./secure')

exports.client =
exports.createClient = function (alice, app_key) {
  var create = handshake.client(alice, app_key)

  return function (bob, cb) {
    return create(bob, secure(cb))
  }

}
exports.server =
exports.createServer = function (bob, authorize, app_key) {
  var create = handshake.server(bob, authorize, app_key)

  return function (cb) {
    return create(secure(cb))
  }

}


