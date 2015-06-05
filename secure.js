var sodium = require('sodium').api
var hash = sodium.crypto_hash_sha256
var pull = require('pull-stream')
var boxes = require('pull-box-stream')

var concat = Buffer.concat

module.exports = function (pub, cb) {

  return function (err, stream, secret, remote_pub) {
    if(err) return cb(err)

    var encrypt = hash(concat([secret, remote_pub]))
    var decrypt = hash(concat([secret, pub]))

    cb(null, {
      source: pull(stream.source, boxes.createUnboxStream(decrypt)),
      sink: pull(boxes.createBoxStream(encrypt), stream.sink)
    })
  }

}


