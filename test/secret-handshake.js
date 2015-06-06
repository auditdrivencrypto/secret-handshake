
var shs = require('../')

var tape = require('tape')
var pull = require('pull-stream')

var sodium = require('sodium').api
var deepEqual = require('deep-equal')

var alice = sodium.crypto_sign_keypair()
var bob   = sodium.crypto_sign_keypair()

var secure = require('../secure')

var app_key = require('crypto').randomBytes(32)

tape('test handshake', function (t) {

  var aliceHS =
    shs.client(alice, app_key)
    (bob.publicKey, secure(function (err, stream) {

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

  var bobHS = shs.server(bob, function (public, cb) {
      t.deepEqual(public, alice.publicKey)

      if(deepEqual(public, alice.publicKey)) cb(null)
      else
        cb(new Error('unauthorized'))

    }, app_key)
    (secure(function (err, stream) {

      if(err) throw err

      pull(stream, pull.through(function (data) {
        console.log('echo:', data.toString())
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
