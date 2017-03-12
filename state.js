
var stateless = require('./stateless')

var sodium      = require('chloride')

var keypair     = sodium.crypto_box_keypair
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

//this is a simple secure handshake,
//the client public key is passed in plain text,

module.exports = State

function State (app_key, local, remote, seed) {

  if(!(this instanceof State)) return new State(app_key, local, remote, seed)

  stateless.initialize.call(this, app_key, local, remote, require('crypto').randomBytes(32), seed)
}

var proto = State.prototype

proto.createChallenge =
function createChallenge () {
  return stateless.createChallenge.call(this)
}

proto.verifyChallenge =
function verifyChallenge (challenge) {
  var state = this
  return !!stateless.verifyChallenge.call(this, challenge)
}


proto.clientVerifyChallenge = function (challenge) {
  var state = this
  return !!stateless.clientVerifyChallenge.call(this, challenge)
}

proto.createClientAuth =
function createClientAuth () {
  return stateless.clientCreateAuth.call(this)
}

proto.verifyClientAuth =
function verifyClientAuth (data) {
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

  return true
}

proto.createServerAccept =
function createServerAccept () {
  var state = this

  //shared key between my local ephemeral key + remote public
  var b_alice = shared(state.local.kx_sk, curvify_pk(state.remote.public))
  state.b_alice = b_alice
  state.secret3 = hash(concat([state.app_key, state.secret, state.a_bob, state.b_alice]))

  var signed = concat([state.app_key, state.remote.hello, state.shash])
  var okay = sign(signed, state.local.secret)
  return box(okay, nonce, state.secret3)
}

proto.verifyServerAccept =
function verifyServerAccept (boxed_okay) {
  return stateless.clientVerifyAccept.call(this, boxed_okay)
}

proto.cleanSecrets =
function cleanSecrets () {
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


