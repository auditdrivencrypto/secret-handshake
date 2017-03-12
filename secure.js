var sodium = require('chloride')
var hash = sodium.crypto_hash_sha256
var pull = require('pull-stream')
var boxes = require('pull-box-stream')

var concat = Buffer.concat

module.exports = function (cb) {

  return function (err, stream, state) {
    if(err) return cb(err)

    var en_nonce = state.remote.app_mac.slice(0, 24)
    var de_nonce = state.local.app_mac.slice(0, 24)

    cb(null, {
      remote: state.remote.publicKey,
      //on the server, attach any metadata gathered
      //during `authorize` call
      auth: state.auth,
      source: pull(
        stream.source,
        boxes.createUnboxStream(state.decryptKey, de_nonce)
      ),
      sink: pull(
        boxes.createBoxStream(state.encryptKey, en_nonce),
        stream.sink
      )
    })
  }

}



