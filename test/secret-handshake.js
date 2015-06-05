
var handshake = require('../')

var tape = require('tape')
var boxes = require('pull-box-stream')
var pull = require('pull-stream')

var sodium = require('sodium').api
var deepEqual = require('deep-equal')

var alice = sodium.crypto_sign_keypair()
var bob   = sodium.crypto_sign_keypair()

function secureStream (stream) {
  return function (encrypt, decrypt) {
    return {
      source: pull(stream.source, boxes.createBoxStream(encrypt)),
      sink: pull(boxes.createUnboxStream(decrypt), stream.sink)
    }
  }
}

function secureClient(clientKey, serverPublicKey, stream) {
  return handshake.client(
    clientKey,
    serverPublicKey,
    secureStream(stream)
  )
}

function secureServer(serverKey, authenticate, stream) {
  return handshake.server(
    serverKey,
    authenticate,
    secureStream(stream)
  )
}


var pair = require('pull-pair')

tape('test handshake', function (t) {

  var aliceHS = secureClient(alice, bob.publicKey, {
    source: pull.values([new Buffer('hello there')]),
    sink: pull.collect(function (err, hello_there) {
      t.equal(hello_there.toString(), 'hello there')
      console.log('output:', hello_there.join(''))
      t.end()
    })
  })

  var bobHS = secureServer(bob, function (pub, cb) {
    cb(deepEqual(pub, alice.pub) && new Error('unauthorized'))
  }, pair())

  pull(
    aliceHS,
    pull.through(console.log.bind(null, 'A->B')),
    bobHS,
    pull.through(console.log.bind(null, 'A<-B')),
    aliceHS
  )

})
