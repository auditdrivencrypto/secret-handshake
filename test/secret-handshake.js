
var shs = require('../')

var tape = require('tape')
var pull = require('pull-stream')

var sodium = require('sodium').api
var deepEqual = require('deep-equal')
var bitflipper = require('pull-bitflipper')

var alice = sodium.crypto_sign_keypair()
var bob   = sodium.crypto_sign_keypair()
var wally = sodium.crypto_sign_keypair()

//var secure = require('../secure')

var app_key = require('crypto').randomBytes(32)

tape('test handshake', function (t) {

  var aliceHS = shs.client(alice, app_key)
    (bob.publicKey, function (err, stream) {

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

    })

  var bobHS = shs.server(bob, function (public, cb) {
      t.deepEqual(public, alice.publicKey)

      if(deepEqual(public, alice.publicKey)) cb(null)
      else
        cb(new Error('unauthorized'))

    }, app_key)
    (function (err, stream) {

      if(err) throw err

      pull(stream, pull.through(function (data) {
        console.log('echo:', data.toString())
      }), stream) //ECHO
    })

  pull(
    aliceHS,
    pull.through(console.log.bind(null, 'A->B')),
    bobHS,
    pull.through(console.log.bind(null, 'A<-B')),
    aliceHS
  )

})

function bitflipTest(t, test) {
  var errs = 0
  var aliceHS = shs.client(alice, app_key)
    (bob.publicKey, function (err) {
      t.ok(err, 'Alice errored')
      if(++errs === 2) t.end()
    })

  var bobHS = shs.server(bob, function (public, cb) {
      t.deepEqual(public, alice.publicKey)

      if(deepEqual(public, alice.publicKey)) cb(null)
      else
        cb(new Error('unauthorized'))

    }, app_key) (function (err) {
      t.ok(err, 'Bob errored')
      if(++errs === 2) t.end()
    })

  test(aliceHS, bobHS)

}

tape('test auth fails when first packet is flipped', function (t) {
  bitflipTest(t, function (aliceHS, bobHS) {
    pull(
      aliceHS,
      bitflipper(1),
      bobHS,
      aliceHS
    )
  })
})

tape('test auth fails when 2nd packet is flipped', function (t) {
  bitflipTest(t, function (aliceHS, bobHS) {
    pull(
      aliceHS,
      bobHS,
      bitflipper(1),
      aliceHS
    )
  })
})

tape('test auth fails when 3rd packet is flipped', function (t) {
  bitflipTest(t, function (aliceHS, bobHS) {
    pull(
      aliceHS,
      bitflipper(2),
      bobHS,
      aliceHS
    )
  })
})

tape('test auth fails when 4th packet is flipped', function (t) {
  bitflipTest(t, function (aliceHS, bobHS) {
    pull(
      aliceHS,
      bobHS,
      bitflipper(2),
      aliceHS
    )
  })
})


tape('test error cb when client is not authorized', function (t) {
  var errs = 0
  var aliceHS = shs.client(alice, app_key)
    (bob.publicKey, function (err) {
      t.ok(err, 'Bob hungup')
      if(++errs === 2) t.end()
    })

  var bobHS = shs.server(bob, function (public, cb) {
      cb(new Error('unauthorized'))
    }, app_key) (function (err) {
      t.ok(err, 'client unauthorized')
      if(++errs === 2) t.end()
    })

  pull(aliceHS, bobHS, aliceHS)
})

tape('test error cb when client get wrong number', function (t) {
  var errs = 0
  var aliceHS = shs.client(alice, app_key)
    (wally.publicKey, function (err) {
      t.ok(err, 'Bob hungup')
      if(++errs === 2) t.end()
    })

  var bobHS = shs.server(bob, function (public, cb) {
      cb(new Error('unauthorized'))
    }, app_key) (function (err) {
      t.ok(err, 'client unauthorized')
      if(++errs === 2) t.end()
    })

  pull(aliceHS, bobHS, aliceHS)
})

