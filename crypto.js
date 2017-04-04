'use strict'
var sodium      = require('chloride')

var keypair     = sodium.crypto_box_seed_keypair
var from_seed   = sodium.crypto_sign_seed_keypair
var shared      = sodium.crypto_scalarmult
var hash        = sodium.crypto_hash_sha256
var sign        = sodium.crypto_sign_detached
var verify      = sodium.crypto_sign_verify_detached
var auth        = sodium.crypto_auth
var verify_auth = sodium.crypto_auth_verify
var curvify_pk  = sodium.crypto_sign_ed25519_pk_to_curve25519
var curvify_sk  = sodium.crypto_sign_ed25519_sk_to_curve25519
var box         = sodium.crypto_secretbox_easy
var unbox       = sodium.crypto_secretbox_open_easy

var concat = Buffer.concat

var nonce = new Buffer(24); nonce.fill(0)

var isBuffer = Buffer.isBuffer

exports.challenge_length = 64
exports.client_auth_length = 16+32+64
exports.server_auth_length = 16+64
exports.mac_length = 16

//both client and server

function assert_length(buf, name, length) {
  if(buf.length !== length)
    throw new Error('expected '+name+' to have length' + length + ', but was:'+buf.length)
}

exports.initialize = function (state) {

  if(state.seed) state.local = from_seed(state.seed)

  //TODO: sodium is missing box_seed_keypair. should make PR for that.

  var _key = from_seed(state.random)
//  var kx = keypair(random)
  var kx_pk = curvify_pk(_key.publicKey)
  var kx_sk = curvify_sk(_key.secretKey)

  state.local = {
    kx_pk: kx_pk,
    kx_sk: kx_sk,
    publicKey: state.local.publicKey,
    secretKey: state.local.secretKey,
    app_mac: auth(kx_pk, state.app_key)
  }

  state.local.kx_pk = kx_pk
  state.local.kx_sk = kx_sk
  state.local.app_mac = auth(kx_pk, state.app_key)
  state.remote = state.remote || {}

  return state
}

exports.createChallenge = function (state) {
  return concat([state.local.app_mac, state.local.kx_pk])
}


exports.verifyChallenge = function (state, challenge) {
  assert_length(challenge, 'challenge', exports.challenge_length)

  var mac = challenge.slice(0, 32)
  var remote_pk = challenge.slice(32, exports.challenge_length)

  if(0 !== verify_auth(mac, remote_pk, state.app_key))
    return null

  state.remote.kx_pk = remote_pk
  state.remote.app_mac = mac
  state.secret = shared(state.local.kx_sk, state.remote.kx_pk)
  state.shash = hash(state.secret)

  return state
}

exports.clean = function (state) {
  // clean away all the secrets for forward security.
  // use a different secret hash(secret3) in the rest of the session,
  // and so that a sloppy application cannot compromise the handshake.

  state.shash.fill(0)
  state.secret.fill(0)
  state.a_bob.fill(0)
  state.b_alice.fill(0)

  state.secret = hash(state.secret3)
  state.encryptKey = hash(concat([state.secret, state.remote.publicKey]))
  state.decryptKey = hash(concat([state.secret, state.local.publicKey]))

  state.secret2.fill(0)
  state.secret3.fill(0)
  state.local.kx_sk.fill(0)

  state.shash = null
  state.secret2 = null
  state.secret3 = null
  state.a_bob = null
  state.b_alice = null
  state.local.kx_sk = null
  return state
}

//client side only (Alice)

exports.clientVerifyChallenge = function (state, challenge) {
  assert_length(challenge, 'challenge', exports.challenge_length)
  state = exports.verifyChallenge(state, challenge)
  if(!state) return null

  //now we have agreed on the secret.
  //this can be an encryption secret,
  //or a hmac secret.

  var a_bob = shared(state.local.kx_sk, curvify_pk(state.remote.publicKey))
  state.a_bob = a_bob
  state.secret2 = hash(concat([state.app_key, state.secret, a_bob]))

  var signed = concat([state.app_key, state.remote.publicKey, state.shash])
  var sig = sign(signed, state.local.secretKey)

  state.local.hello = Buffer.concat([sig, state.local.publicKey])
  return state
}

exports.clientCreateAuth = function (state) {
  return box(state.local.hello, nonce, state.secret2)
}

exports.clientVerifyAccept = function (state, boxed_okay) {
  assert_length(boxed_okay, 'server_auth', exports.server_auth_length)

  var b_alice = shared(curvify_sk(state.local.secretKey), state.remote.kx_pk)
  state.b_alice = b_alice
  state.secret3 = hash(concat([state.app_key, state.secret, state.a_bob, state.b_alice]))

  var sig = unbox(boxed_okay, nonce, state.secret3)
  if(!sig) return null
  var signed = concat([state.app_key, state.local.hello, state.shash])
  if(!verify(sig, signed, state.remote.publicKey))
      return null
  return state
}

//server side only (Bob)

exports.serverVerifyAuth = function (state, data) {
  assert_length(data, 'client_auth', exports.client_auth_length)

  var a_bob = shared(curvify_sk(state.local.secretKey), state.remote.kx_pk)
  state.a_bob = a_bob
  state.secret2 = hash(concat([state.app_key, state.secret, a_bob]))

  state.remote.hello = unbox(data, nonce, state.secret2)
  if(!state.remote.hello)
    return null

  var sig = state.remote.hello.slice(0, 64)
  var publicKey = state.remote.hello.slice(64, exports.client_auth_length)

  var signed = concat([state.app_key, state.local.publicKey, state.shash])
  if(!verify(sig, signed, publicKey))
    return null

  state.remote.publicKey = publicKey
  //shared key between my local ephemeral key + remote public
  var b_alice = shared(state.local.kx_sk, curvify_pk(state.remote.publicKey))
  state.b_alice = b_alice
  state.secret3 = hash(concat([state.app_key, state.secret, state.a_bob, state.b_alice]))

  return state

}

exports.serverCreateAccept = function (state) {
  var signed = concat([state.app_key, state.remote.hello, state.shash])
  var okay = sign(signed, state.local.secretKey)
  return box(okay, nonce, state.secret3)
}

exports.toKeys = function (keys) {
  if(isBuffer(keys, 32))
    return sodium.crypto_sign_seed_keypair(keys)
  return keys
}

