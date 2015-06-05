var sodium = require('sodium').api

var keypair = sodium.crypto_box_keypair
var concat = Buffer.concat
var shared = sodium.crypto_scalarmult

var handshake = require('./handshake')
var hash = sodium.crypto_hash_sha256
var sign = sodium.crypto_sign_detached
var verify = sodium.crypto_sign_verify_detached
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

//client is Alice
//create the client stream with the public key you expect to connect to.
exports.client =
exports.createClientStream = function (alice, bob_pub, createStream) {
  var alice_kx = keypair()
  return handshake(function (shake) {
    shake.write(alice_kx.publicKey)

    shake.read(KEY_EX_LENGTH, function (err, bob_kx_pub) {
      var secret = shared(alice_kx.secretKey, bob_kx_pub)
      var shash = hash(secret)
      //now we have agreed on the secret.
      //this can be an encryption secret,
      //or a hmac secret.

      var sig = sign(concat([bob_pub, shash]), alice.secretKey)

      //32 + 64 = 96 bytes
      var hello = Buffer.concat([alice.publicKey, sig])
      shake.write(hello)

      shake.read(server_auth_length, function (err, sig) {
        if(!verify(sig, concat([hello, shash]), bob_pub))
          throw new Error('server not authenticated')

        shake.ready(createStream(
          hash(concat([secret, bob_kx_pub])),
          hash(concat([secret, alice_kx.publicKey]))
        ))
      })
    })
  })
}


//server is Bob.
exports.server =
exports.createServerStream = function (bob, authorize, createStream) {

  return handshake(function (shake) {
    shake.read(KEY_EX_LENGTH, function (err, alice_kx_pub) {
      //ephemeral key exchange
      var bob_kx = keypair()
      var secret = shared(bob_kx.secretKey, alice_kx_pub)

      var shash = hash(secret)
      shake.write(bob_kx.publicKey)
      shake.read(client_auth_length, function (err, hello) {

        var alice_pub = hello.slice(0, 32)
        var sig = hello.slice(32, client_auth_length)

        if(!verify(sig, concat([bob.publicKey, shash]), alice_pub))
          throw new Error('server hang up - wrong number')

        //check if the user wants to speak to alice.
        authorize(alice_pub, function (err) {
          if(err)
            throw err
          //alice is okay, send the okay back.
          //just send the signature. 64 bytes.

          //by signing the secret, only a participant in the exchange
          //can create a valid authentication.
          var okay = sign(concat([hello, shash]), bob.secretKey)

          shake.write(okay)
          //we are now ready!
          //we can already cryptographically prove that alice
          //wants to talk to us, because she signed our pubkey.
          shake.ready(createStream(
            hash(concat([secret, alice_kx_pub])),
            hash(concat([secret, bob_kx.publicKey]))
          ))
        })
      })
    })
  })
}

