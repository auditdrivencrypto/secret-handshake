
var shs = require('../')

var tape = require('tape')
var pull = require('pull-stream')

var cl = require('chloride')
var deepEqual = require('deep-equal')
var bitflipper = require('pull-bitflipper')
var Hang = require('pull-hang')

function hash (str) {
  return cl.crypto_hash_sha256(new Buffer(str))
}

var alice = cl.crypto_sign_seed_keypair(hash('alice'))
var bob   = cl.crypto_sign_seed_keypair(hash('bob'))
var wally = cl.crypto_sign_seed_keypair(hash('wally'))

//var secure = require('../secure')

var app_key = hash('app_key')

function unauthorized (_, cb) {
  cb(new Error('unauthorized'))
}

function authorized (_, cb) {
  cb()
}

tape('test handshake', function (t) {

  var aliceHS = shs.client(alice, app_key, 100)
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

  var r = Math.random()
  var bobHS = shs.server(bob, function (public, cb) {
      t.deepEqual(public, alice.publicKey)

      if(deepEqual(public, alice.publicKey)) cb(null, {okay: true, random: r})
      else
        cb(new Error('unauthorized'))

    }, app_key, 100)
      (function (err, stream) {

        if(err) throw err

        t.deepEqual(stream.auth, {okay: true, random: r})
        pull(stream, pull.through(function (data) {
          console.log('echo:', data.toString())
        }), stream) //ECHO
      })

  pull(
    aliceHS,
    pull.through(console.log.bind(console, 'A->B')),
    bobHS,
    pull.through(console.log.bind(console, 'A<-B')),
    aliceHS
  )

})

function bitflipTest(t, test) {
  var errs = 0
  var aliceHS = shs.client(alice, app_key, 100)
    (bob.publicKey, function (err) {
      t.ok(err, 'Alice errored')
      if(++errs === 2) t.end()
    })

  var bobHS = shs.server(bob, function (public, cb) {
      t.deepEqual(public, alice.publicKey)

      if(deepEqual(public, alice.publicKey)) cb(null)
      else
        cb(new Error('unauthorized'))

    }, app_key, 100)
      (function (err) {
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
  var aliceHS = shs.client(alice, app_key, 100)
    (bob.publicKey, function (err) {
      t.ok(err, 'Bob hungup')
      if(++errs === 2) t.end()
    })

  var bobHS = shs.server(bob, unauthorized, app_key, 100)
      (function (err) {
        t.ok(err, 'client unauthorized')
        if(++errs === 2) t.end()
      })

  pull(aliceHS, bobHS, aliceHS)
})

tape('test error cb when client get wrong number', function (t) {
  var errs = 0
  var aliceHS = shs.client(alice, app_key, 100)
    (wally.publicKey, function (err) {
      t.ok(err, 'Bob hungup')
      if(++errs === 2) t.end()
    })

  var bobHS = shs.server(bob, unauthorized, app_key, 100)
      (function (err) {
        t.ok(err, 'client unauthorized')
        if(++errs === 2) t.end()
      })

  pull(aliceHS, bobHS, aliceHS)
})


tape('error if created without public key', function (t) {

  var aliceHS = shs.client(alice, app_key, 100)
  t.throws(function () {
    aliceHS()
  })
  t.end()
})

tape('unauthorized connection must cb once', function (t) {
  t.plan(2)
  var n = 2
  var aliceHS = shs.client(alice, app_key, 100)
  var bobHS = shs.server(bob, authorized, app_key, 100)

  var as = aliceHS(bob.publicKey, function (err, stream) {
    console.log('Alice')
    t.ok(err, 'client connect should fail')
    next()
  })

  pull(as, bobHS(function (err, stream) {
    console.log('Bob')
    t.ok(err, 'server connect should fail')
    next()
  }), as)

  function next () {
    if(--n) return
    t.end()
  }


})

tape('client timeout error if there is no response', function (t) {

  var aliceHS = shs.client(alice, app_key, 100)
    (bob.publicKey, function (err, stream) {
      t.ok(err)
      t.end()
    })

  pull(
    Hang(),
    aliceHS
  )
  //do nothing, so aliceHS should timeout
})

tape('server timeout error if there is no response', function (t) {

  var bobHS = shs.server(alice, authorized, app_key, 100)
    (function (err, stream) {
      t.ok(err)
      t.end()
    })

  pull(
    Hang(),
    bobHS
  )
  //do nothing, so aliceHS should timeout
})

tape('test handshake', function (t) {

  var aliceHS = shs.client(null, app_key, 100)
    (bob.publicKey, hash('alice'), function (err, stream) {

      if(err) throw err

    })

  var r = Math.random()
  var bobHS = shs.server(bob, function (public, cb) {
      t.deepEqual(public, alice.publicKey)
      cb(null, {okay: true, random: r})
    }, app_key, 100)
      (function (err, stream) {
        if(err) throw err

        t.deepEqual(stream.auth, {okay: true, random: r})
        t.end()
      })

  pull(
    aliceHS,
    bobHS,
    aliceHS
  )

})

