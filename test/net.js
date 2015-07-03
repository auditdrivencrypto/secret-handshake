
var net = require('net')
var pull = require('pull-stream')
var toPull = require('stream-to-pull-stream')
var tape = require('tape')

var sodium = require('sodium/build/Release/sodium')

var alice = sodium.crypto_sign_keypair()
var bob = sodium.crypto_sign_keypair()

var app_key = require('crypto').randomBytes(32)

var shs = require('../')

tape('test with net', function (t) {

  var createServer = shs.createServer(bob, function (pub, cb) {
    cb(null, true) //accept
  }, app_key)

  var createClient = shs.createClient(alice, app_key)


  var PORT = 45034

  var server = net.createServer(function (stream) {

    stream = toPull.duplex(stream)

    pull(
      stream,
      createServer(function (err, stream) {
        console.log('server connected', err, stream)

        pull(stream, stream) //echo
      }),
      stream
    )

  }).listen(PORT, function () {

    var stream = toPull.duplex(net.connect(PORT))

    console.log('CLIENT connect')
    pull(
      stream,
      createClient(bob.publicKey, function (err, stream) {
        console.log('client connected', err, stream)
        pull(
          pull.values([new Buffer('HELLO')]),
          stream,
          pull.collect(function (err, data) {
            t.notOk(err)
            t.deepEqual(Buffer.concat(data), new Buffer('HELLO'))
            server.close()
            t.end()
          })
        )
      }),
      stream
    )

  })

})

tape('test with net', function (t) {
  var n = 2
  t.plan(2)
  var createServer = shs.createServer(bob, function (pub, cb) {
    cb() //reject, with no reason
  }, app_key)

  var createClient = shs.createClient(alice, app_key)

  var PORT = 45035

  var server = net.createServer(function (stream) {

    stream = toPull.duplex(stream)

    pull(
      stream,
      createServer(function (err, stream) {
        t.ok(err)
        console.log('server connected', err, stream)
        next()
      }),
      stream
    )

  }).listen(PORT, function () {

    var stream = toPull.duplex(net.connect(PORT))

    console.log('CLIENT connect')
    pull(
      stream,
      createClient(bob.publicKey, function (err, stream) {
        console.log('client connected', err, stream)
        t.ok(err)
        next()
      }),
      stream
    )

  })

  function next() {
    if(--n) return
    server.close()
  }

})
