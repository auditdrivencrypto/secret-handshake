var sodium = require('sodium').api
var pull = require('pull-stream')

var keypair = sodium.crypto_box_keypair
var shared = sodium.crypto_scalarmult
var hash = sodium.crypto_hash_sha256
var sign = sodium.crypto_sign_detached
var verify = sodium.crypto_sign_verify_detached
var auth = sodium.crypto_auth
var verify_auth = sodium.crypto_auth_verify

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

function createState(app_key, local, remote) {
  return {
    app_key: app_key,
    local: {
      public: local.publicKey, secret: local.secretKey
    }, remote: {
      public: remote ? remote : null
    }
  }
}

function createChallenge (state) {
  var kx = keypair()
  state.local.kx_pk = kx.publicKey
  state.local.kx_sk = kx.secretKey
  state.local.app_mac = auth(state.local.kx_pk, state.app_key)
  return concat([state.local.app_mac, state.local.kx_pk])
}

function verifyChallenge (challenge, state) {
  var mac = challenge.slice(0, 32)
  var remote_pk = challenge.slice(32, challenge.length)
  if(0 !== verify_auth(mac, remote_pk, state.app_key))
    return null

  state.remote.kx_pk = remote_pk
  state.secret = shared(state.local.kx_sk, state.remote.kx_pk)
  state.shash = hash(state.secret)

  return true
}

function createClientAuth (state) {
  //now we have agreed on the secret.
  //this can be an encryption secret,
  //or a hmac secret.

  // shared(local.kx, remote.public)
  var a_bob = shared(state.local.kx_sk, curvify_pk(state.remote.public))
  state.secret2 = hash(concat([state.secret, a_bob]))

  var sig = sign(concat([state.remote.public, state.shash]), state.local.secret)

  state.local.hello = Buffer.concat([sig, state.local.public])
  return box(state.local.hello, nonce, state.secret2)
}

function verifyClientAuth (data, state) {
  var a_bob = shared(curvify_sk(state.local.secret), state.remote.kx_pk)
  state.secret2 = hash(concat([state.secret, a_bob]))

  state.remote.hello = unbox(data, nonce, state.secret2)

  var sig = state.remote.hello.slice(0, 64)
  var public = state.remote.hello.slice(64, client_auth_length)

  if(!verify(sig, concat([state.local.public, state.shash]), public))
    return null

  state.remote.public = public

  return true
}

function createServerAccept (state) {
  //shared key between my local ephemeral key + remote public
  var b_alice = shared(state.local.kx_sk, curvify_pk(state.remote.public))
  state.secret3 = hash(concat([state.secret2, b_alice]))

  var shash = state.shash

  var okay = sign(concat([state.remote.hello, shash]), state.local.secret)
  return box(okay, nonce, state.secret3)
}

function verifyServerAccept (boxed_okay, state) {
  var b_alice = shared(curvify_sk(state.local.secret), state.remote.kx_pk)
  state.secret3 = hash(concat([state.secret2, b_alice]))

  var sig = unbox(boxed_okay, nonce, state.secret3)
  if(!verify(sig, concat([state.local.hello, state.shash]), state.remote.public))
      return null
  return true
}

//client is Alice
//create the client stream with the public key you expect to connect to.
exports.client =
exports.createClientStream = function (alice, app_key) {

  return function (bob_pub, cb) {
    var state = createState(app_key, alice, bob_pub)

    var stream = Handshake()
    var shake = stream.handshake
    delete stream.handshake

    shake.write(createChallenge(state))

    shake.read(32+KEY_EX_LENGTH, function (err, msg) {
      //create the challenge first, because we need to generate a local key
      if(!verifyChallenge(msg, state))
        throw new Error('wrong protocol (version?)')

      shake.write(createClientAuth(state))

      shake.read(16+server_auth_length, function (err, boxed_sig) {
        if(!verifyServerAccept(boxed_sig, state))
          throw new Error('server not authenticated')

        cb(null, shake.rest(), state)
      })
    })

    return stream
  }
}

//server is Bob.
exports.server =
exports.createServerStream = function (bob, authorize, app_key) {

  return function (cb) {
    var state = createState(app_key, bob)
    var stream = Handshake()

    var shake = stream.handshake
    delete stream.handshake

    shake.read(32+KEY_EX_LENGTH, function (err, challenge) {
      var c = createChallenge(state)
      if(!verifyChallenge(challenge, state))
        throw new Error('wrong protocol/version')

      shake.write(c)
      shake.read(16+client_auth_length, function (err, hello) {
        if(!verifyClientAuth(hello, state))
          throw new Error('unauthenticated client')

        //check if the user wants to speak to alice.
        authorize(state.remote.public, function (err) {
          if(err) throw err
          shake.write(createServerAccept(state))
          cb(null, shake.rest(), state)
        })
      })
    })
    return stream
  }
}

