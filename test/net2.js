
var netshs = require('../net')


var pull = require('pull-stream')
var tape = require('tape')

var sodium = require('sodium/build/Release/sodium')

var alice = sodium.crypto_sign_keypair()
var bob = sodium.crypto_sign_keypair()

var app_key = require('crypto').randomBytes(32)

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

tape('test with net', function (t) {

  var PORT = 45034

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

tape('test with net', function (t) {

  var bobN = netshs({
    keys: bob,
    appKey: app_key,
    authenticate: function (pub, cb) {
      cb() //reject, with no reason
    }
  })

  var PORT = 45035

  var server = bobN.createServer(function (stream) {
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

