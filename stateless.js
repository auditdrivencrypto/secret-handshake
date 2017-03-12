
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


exports.initialize = function (app_key, local, remote, random, seed) {

  var self = this || {}

  if(seed) local = from_seed(seed)

  //TODO: sodium is missing box_seed_keypair. should make PR for that.
  var _key = from_seed(random)

  self.app_key = app_key
//  var kx = keypair(random)
  self.local = {
    kx_pk: curvify_pk(_key.publicKey),
    kx_sk: curvify_sk(_key.secretKey),
    public: local.publicKey,
    secret: local.secretKey
  }
  self.remote = {
    public: remote || null
  }

  return self

}


