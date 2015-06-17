var sodium = require('sodium').api
var hash = sodium.crypto_hash_sha256
var pull = require('pull-stream')
var boxes = require('pull-box-stream')

var concat = Buffer.concat

module.exports = function (cb) {

  return function (err, stream, state) {
    if(err) return cb(err)

    var en_key = hash(concat([state.secret, state.remote.public]))
    var de_key = hash(concat([state.secret, state.local.public]))

    var en_nonce = state.remote.app_mac.slice(0, 24)
    var de_nonce = state.local.app_mac.slice(0, 24)

    cb(null, {
      remote: state.remote.public,
      source: pull(
        stream.source,
        boxes.createUnboxStream(de_key, de_nonce)
      ),
      sink: pull(
        boxes.createBoxStream(en_key, en_nonce),
        stream.sink
      )
    })
  }

}


