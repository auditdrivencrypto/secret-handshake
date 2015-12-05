
var netshs = require('../net')


var pull = require('pull-stream')
var tape = require('tape')

var cl = require('chloride')

function hash (str) {
  return cl.crypto_hash_sha256(new Buffer(str))
}

var alice = cl.crypto_sign_seed_keypair(hash('alice'))
var bob = cl.crypto_sign_seed_keypair(hash('bob'))

var crypto = require('crypto')
var app_key = crypto.randomBytes(32)

var shs = require('../')

var bobN = netshs({
  keys: bob,
  appKey: app_key,
  authenticate: function (pub, cb) {
    cb(null, true) //accept
  }
})

var aliceN = netshs({
  keys: alice,
  appKey: app_key,
  //alice doesn't need authenticate
  //because she is the client.
})
var PORT = 45034

tape('test net.js, correct, callback', function (t) {


  var server = bobN.createServer(function (stream) {
    t.deepEqual(stream.remote, alice.publicKey)
    pull(stream, pull.through(console.log), stream) //echo
  }).listen(PORT, function () {
    aliceN.connect(
      {host: 'localhost', port: PORT, key: bob.publicKey},
      function (err, stream) {
        if(err) throw err
        t.deepEqual(stream.remote, bob.publicKey)
        pull(
          pull.values([new Buffer('HELLO')]),
          stream,
          pull.collect(function (err, data) {
            if(err) throw err
            t.notOk(err)
            t.deepEqual(Buffer.concat(data), new Buffer('HELLO'))
            server.close()
            t.end()
          })
        )
      }
    )
  })

})

tape('test net.js, correct, stream directly', function (t) {

  var server = bobN.createServer(function (stream) {
    t.deepEqual(stream.remote, alice.publicKey)
    pull(stream, pull.through(console.log), stream) //echo
  }).listen(PORT, function () {
    pull(
      pull.values([new Buffer('HELLO')]),
      aliceN.connect({port: PORT, key: bob.publicKey}),
      pull.collect(function (err, data) {
        if(err) throw err
        t.notOk(err)
        t.deepEqual(Buffer.concat(data), new Buffer('HELLO'))
        server.close()
        t.end()
      })
    )
  })

})

var bobN2 = netshs({
  keys: bob,
  appKey: app_key,
  authenticate: function (pub, cb) {
    cb() //reject, with no reason
  }
})

tape('test net, error, callback', function (t) {

  var server = bobN2.createServer(function (stream) {
    throw new Error('this should never be called')
  }).listen(PORT, function () {

    console.log('CLIENT connect')
    aliceN.connect({
      port: PORT,
      key: bob.publicKey
    }, function (err, stream) {
        console.log('client connected', err, stream)
        t.ok(err)
        t.end()
        server.close()
    })
  })

})


tape('test net, error, stream', function (t) {

  var server = bobN2.createServer(function (stream) {
    throw new Error('this should never be called')
  }).listen(PORT, function () {

    pull(
      aliceN.connect({
        port: PORT,
        key: bob.publicKey
      }),
      pull.collect(function (err, ary) {
          t.ok(err)
          t.end()
          server.close()
      })
    )
  })

})

tape('test net, create seed cap', function (t) {

  var seed = crypto.randomBytes(32)
  var keys = cl.crypto_sign_seed_keypair(seed)

  var seedN = netshs({
    seed: seed,
    appKey: app_key,
    //alice doesn't need authenticate
    //because she is the client.
  })

  var server = bobN.createServer(function (stream) {
    t.deepEqual(stream.remote, keys.publicKey)
    stream.source(true, function () {})
    server.close()
    t.end()
  }).listen(PORT, function () {

    seedN.connect({port: PORT, key: bob.publicKey})

  })

})
