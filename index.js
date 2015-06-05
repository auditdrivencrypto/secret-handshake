var sodium = require('sodium').api
var pull = require('pull-stream')

var keypair = sodium.crypto_box_keypair
var shared = sodium.crypto_scalarmult
var hash = sodium.crypto_hash_sha256
var sign = sodium.crypto_sign_detached
var verify = sodium.crypto_sign_verify_detached

var Handshake = require('./handshake')

var concat = Buffer.concat

//this is a simple secure handshake,
//the client public key is passed in plain text,

function box (msg, nonce, key) {
  var b = sodium.crypto_secretbox(msg, nonce, key)
  return b.slice(16, b.length)
}

var zeros = new Buffer(16); zeros.fill(0)

function unbox (ciphermsg, nonce, key) {
  return sodium.crypto_secretbox_open(
    concat([zeros, ciphermsg]),
    nonce, key
  )
}

var KEY_EX_LENGTH = keypair().publicKey.length

var challenge_length = 32
var client_auth_length = 32+64
var server_auth_length = 64
var mac_length = 16

var nonce = new Buffer(24); nonce.fill(0)

var curvify_pk = sodium.crypto_sign_ed25519_pk_to_curve25519
var curvify_sk = sodium.crypto_sign_ed25519_sk_to_curve25519

//client is Alice
//create the client stream with the public key you expect to connect to.
exports.client =
exports.createClientStream = function (alice, bob_pub, cb) {
  var stream = Handshake()
  var shake = stream.handshake
  delete stream.handshake

  var alice_kx = keypair()
  shake.write(alice_kx.publicKey)

  shake.read(KEY_EX_LENGTH, function (err, bob_kx_pub) {
    var secret = shared(alice_kx.secretKey, bob_kx_pub)
    var shash = hash(secret)
    //now we have agreed on the secret.
    //this can be an encryption secret,
    //or a hmac secret.

    var a_bob = shared(alice_kx.secretKey, curvify_pk(bob_pub))

    var secret2 = hash(concat([secret, a_bob]))

    var sig = sign(concat([bob_pub, shash]), alice.secretKey)

    //32 + 64 = 96 bytes
    var hello = Buffer.concat([alice.publicKey, sig])
    shake.write(box(hello, nonce, secret2))

    shake.read(16+server_auth_length, function (err, boxed_sig) {

      var b_alice = shared(curvify_sk(alice.secretKey), bob_kx_pub)
      var secret3 = hash(concat([secret2, b_alice]))
      var sig = unbox(boxed_sig, nonce, secret3)
      if(!verify(sig, concat([hello, shash]), bob_pub))
        throw new Error('server not authenticated')

      cb(null, shake.rest(), secret3, bob_pub)
    })
  })

  return stream
}


//server is Bob.
exports.server =
exports.createServerStream = function (bob, authorize, cb) {

  var stream = Handshake()

  var shake = stream.handshake
  delete stream.handshake

  shake.read(KEY_EX_LENGTH, function (err, alice_kx_pub) {
    //ephemeral key exchange
    var bob_kx = keypair()
    var secret = shared(bob_kx.secretKey, alice_kx_pub)

    var shash = hash(secret)
    shake.write(bob_kx.publicKey)
    shake.read(16+client_auth_length, function (err, boxed_hello) {

      var a_bob = shared(curvify_sk(bob.secretKey), alice_kx_pub)
      var secret2 = hash(concat([secret, a_bob]))

      var hello = unbox(boxed_hello, nonce, secret2)
      var alice_pub = hello.slice(0, 32)
      var sig = hello.slice(32, client_auth_length)

      if(!verify(sig, concat([bob.publicKey, shash]), alice_pub))
        throw new Error('server hang up - wrong number')

      //check if the user wants to speak to alice.
      authorize(alice_pub, function (err) {
        if(err) throw err
        //alice is okay, send the okay back.
        //just send the signature. 64 bytes.

        //by signing the secret, only a participant in the exchange
        //can create a valid authentication.
        var b_alice = shared(bob_kx.secretKey, curvify_pk(alice_pub))
        var secret3 = hash(concat([secret2, b_alice]))

        var okay = sign(concat([hello, shash]), bob.secretKey)

        shake.write(box(okay, nonce, secret3))
        //we are now ready!
        //we can already cryptographically prove that alice
        //wants to talk to us, because she signed our pubkey.
        cb(null, shake.rest(), secret3, alice_pub)
      })
    })
  })

  return stream
}

