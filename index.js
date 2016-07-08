var handshake = require('./handshake')
var secure = require('./secure')
var cl = require('chloride')

function isBuffer(buf, len) {
  return Buffer.isBuffer(buf) && buf.length === len
}

function toKeys(seed) {
  if(isBuffer(seed.publicKey, 32) && isBuffer(seed.secretKey, 64)) return seed
  if(isBuffer(seed, 32))
    return cl.crypto_sign_seed_keypair(seed)
  throw new Error('keypair or seed must be provided')
}

exports.client =
exports.createClient = function (alice, app_key, timeout) {
  var create = handshake.client(toKeys(alice), app_key, timeout)

  return function (bob, cb) {
    if(!isBuffer(bob, 32))
      throw new Error('createClient *must* be passed a public key')
    return create(bob, secure(cb))
  }

}
exports.server =
exports.createServer = function (bob, authorize, app_key, timeout) {
  var create = handshake.server(toKeys(bob), authorize, app_key, timeout)

  return function (cb) {
    return create(secure(cb))
  }

}





