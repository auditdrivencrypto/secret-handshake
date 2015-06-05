
var shs = require('../')

var tape = require('tape')
var pull = require('pull-stream')

var sodium = require('sodium').api
var deepEqual = require('deep-equal')

var alice = sodium.crypto_sign_keypair()
var bob   = sodium.crypto_sign_keypair()

var secure = require('../secure')

tape('test handshake', function (t) {

  var aliceHS = shs.client(alice, bob.publicKey,
    secure(alice.publicKey, function (err, stream) {

      if(err) throw err

      pull(
        pull.values([new Buffer('hello there')]),
        stream,
        pull.collect(function (err, hello_there) {
          t.equal(hello_there.toString(), 'hello there')
          console.log('output:', hello_there.join(''))
          t.end()
        })
      )

    }))

  var bobHS = shs.server(bob, function (pub, cb) {
    console.log('AUTHORIZED?', pub, alice.publicKey)
    t.deepEqual(pub, alice.publicKey)
    cb(deepEqual(pub, alice.publicKey) ? null : new Error('unauthorized') )
  }, secure(bob.publicKey, function (err, stream) {

    if(err) throw err

    pull(stream, pull.through(function (data) {
      console.log(data.toString())
    }), stream) //ECHO
  }))

  pull(
    aliceHS,
    pull.through(console.log.bind(null, 'A->B')),
    bobHS,
    pull.through(console.log.bind(null, 'A<-B')),
    aliceHS
  )

})
