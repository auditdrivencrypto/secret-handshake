var sodium = require('sodium').api
var hash = sodium.crypto_hash_sha256
var pull = require('pull-stream')
var boxes = require('pull-box-stream')

var concat = Buffer.concat

module.exports = function (cb) {

  return function (err, stream, state) {
    if(err) return cb(err)

    var encrypt = hash(concat([state.secret3, state.remote.public]))
    var decrypt = hash(concat([state.secret3, state.local.public]))

    cb(null, {
      source: pull(stream.source, boxes.createUnboxStream(decrypt)),
      sink: pull(boxes.createBoxStream(encrypt), stream.sink)
    })
  }

}


