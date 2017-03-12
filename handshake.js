var pull = require('pull-stream')

var Handshake = require('pull-handshake')
var stateless = require('./stateless')
var crypto = require('crypto')

var challenge_length = 64
var client_auth_length = 16+32+64
var server_auth_length = 16+64
var mac_length = 16

//client is Alice
//create the client stream with the public key you expect to connect to.
exports.client =
exports.createClientStream = function (alice, app_key, timeout) {

  return function (bob_pub, seed, cb) {
    if('function' == typeof seed)
      cb = seed, seed = null

    //alice may be null.
    var state = stateless.initialize({
      app_key: app_key,
      local: alice,
      remote: {publicKey: bob_pub},
      seed: seed,
      random: crypto.randomBytes(32)
    })

    var stream = Handshake({timeout: timeout}, cb)
    var shake = stream.handshake
    stream.handshake = null

    function abort(err, reason) {
      if(err && err !== true) shake.abort(err, cb)
      else                    shake.abort(new Error(reason), cb)
    }

    shake.write(stateless.createChallenge(state))

    shake.read(challenge_length, function (err, msg) {
      if(err) return abort(err, 'challenge not accepted')
      //create the challenge first, because we need to generate a local key
      if(!(state = stateless.clientVerifyChallenge(state, msg)))
        return abort(null, 'wrong protocol (version?)')

      shake.write(stateless.clientCreateAuth(state))

      shake.read(server_auth_length, function (err, boxed_sig) {
        if(err) return abort(err, 'hello not accepted')

        if(!(state = stateless.clientVerifyAccept(state, boxed_sig)))
          return abort(null, 'server not authenticated')

        cb(null, shake.rest(), state = stateless.clean(state))
      })
    })

    return stream
  }
}

//server is Bob.
exports.server =
exports.createServerStream = function (bob, authorize, app_key, timeout) {

  return function (cb) {
    var state = stateless.initialize({
      app_key: app_key,
      local: bob,
      //note, the server doesn't know the remote until it receives ClientAuth
      random: crypto.randomBytes(32)
    })
    var stream = Handshake({timeout: timeout}, cb)

    var shake = stream.handshake
    stream.handshake = null

    function abort (err, reason) {
      if(err && err !== true) shake.abort(err, cb)
      else                    shake.abort(new Error(reason), cb)
    }

    shake.read(challenge_length, function (err, challenge) {
      if(err) return abort(err, 'expected challenge')
      if(!(state = stateless.verifyChallenge(state, challenge)))
        return shake.abort(new Error('wrong protocol/version'))

      shake.write(stateless.createChallenge(state))
      shake.read(client_auth_length, function (err, hello) {
        if(err) return abort(err, 'expected hello')
        if(!(state = stateless.serverVerifyAuth(state, hello)))
          return abort(null, 'wrong number')

        //check if the user wants to speak to alice.
        authorize(state.remote.publicKey, function (err, auth) {
          if(auth == null && !err) err = new Error('client unauthorized')
          if(!auth) return abort(err, 'client authentication rejected')
          state.auth = auth
          shake.write(stateless.serverCreateAccept(state))
          cb(null, shake.rest(), state = stateless.clean(state))
        })
      })
    })
    return stream
  }
}

