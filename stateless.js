
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

var challenge_length = 64
var client_auth_length = 16+32+64
var server_auth_length = 16+64
var mac_length = 16

//both client and server

exports.initialize = function (app_key, local, remote, random, seed) {

  var state = this

  if(seed) local = from_seed(seed)

  //TODO: sodium is missing box_seed_keypair. should make PR for that.
  var _key = from_seed(random)

  state.app_key = app_key
//  var kx = keypair(random)
  var kx_pk = curvify_pk(_key.publicKey)
  var kx_sk = curvify_sk(_key.secretKey)
  state.local = {
    kx_pk: kx_pk,
    kx_sk: kx_sk,
    public: local.publicKey,
    secret: local.secretKey,
    app_mac: auth(kx_pk, app_key)
  }
  state.remote = {
    public: remote || null
  }

  return state
}

exports.createChallenge = function () {
  var state = this
  return concat([state.local.app_mac, state.local.kx_pk])
}


exports.verifyChallenge = function (challenge) {
  var state = this

  var mac = challenge.slice(0, 32)
  var remote_pk = challenge.slice(32, challenge.length)
  if(0 !== verify_auth(mac, remote_pk, state.app_key))
    return null

  state.remote.kx_pk = remote_pk
  state.remote.app_mac = mac
  state.secret = shared(state.local.kx_sk, state.remote.kx_pk)
  state.shash = hash(state.secret)

  return state
}

exports.clean = function () {
  var state = this

  // clean away all the secrets for forward security.
  // use a different secret hash(secret3) in the rest of the session,
  // and so that a sloppy application cannot compromise the handshake.

  delete state.local.secret
  state.shash.fill(0)
  state.secret.fill(0)
  state.a_bob.fill(0)
  state.b_alice.fill(0)
  state.secret = hash(state.secret3)
  state.secret2.fill(0)
  state.secret3.fill(0)
  state.local.kx_sk.fill(0)

  delete state.shash
  delete state.secret2
  delete state.secret3
  delete state.a_bob
  delete state.b_alice
  delete state.local.kx_sk
  return state
}

//client side only (Alice)

exports.clientVerifyChallenge = function (challenge) {

  var state = this
  state = exports.verifyChallenge.call(state, challenge)
  if(!state) return null

    //now we have agreed on the secret.
  //this can be an encryption secret,
  //or a hmac secret.

  // shared(local.kx, remote.public)
  var a_bob = shared(state.local.kx_sk, curvify_pk(state.remote.public))
  state.a_bob = a_bob
  state.secret2 = hash(concat([state.app_key, state.secret, a_bob]))

  var signed = concat([state.app_key, state.remote.public, state.shash])
  var sig = sign(signed, state.local.secret)

  state.local.hello = Buffer.concat([sig, state.local.public])

  return state
}

exports.clientCreateAuth = function () {
  var state = this
  return box(state.local.hello, nonce, state.secret2)
}

exports.clientVerifyAccept = function (boxed_okay) {
  var state = this

  var b_alice = shared(curvify_sk(state.local.secret), state.remote.kx_pk)
  state.b_alice = b_alice
//  state.secret3 = hash(concat([state.secret2, b_alice]))
  state.secret3 = hash(concat([state.app_key, state.secret, state.a_bob, state.b_alice]))

  var sig = unbox(boxed_okay, nonce, state.secret3)
  if(!sig) return null
  var signed = concat([state.app_key, state.local.hello, state.shash])
  if(!verify(sig, signed, state.remote.public))
      return null
  return state
}

//server side only (Bob)

exports.serverVerifyAuth = function (data) {

  var state = this

  var a_bob = shared(curvify_sk(state.local.secret), state.remote.kx_pk)
  state.a_bob = a_bob
  state.secret2 = hash(concat([state.app_key, state.secret, a_bob]))

  state.remote.hello = unbox(data, nonce, state.secret2)
  if(!state.remote.hello)
    return null

  var sig = state.remote.hello.slice(0, 64)
  var public = state.remote.hello.slice(64, client_auth_length)

  var signed = concat([state.app_key, state.local.public, state.shash])
  if(!verify(sig, signed, public))
    return null

  state.remote.public = public
  //shared key between my local ephemeral key + remote public
  var b_alice = shared(state.local.kx_sk, curvify_pk(state.remote.public))
  state.b_alice = b_alice
  state.secret3 = hash(concat([state.app_key, state.secret, state.a_bob, state.b_alice]))

  return state

}

exports.serverCreateAccept = function () {
  var state = this
  var signed = concat([state.app_key, state.remote.hello, state.shash])
  var okay = sign(signed, state.local.secret)
  return box(okay, nonce, state.secret3)

}


