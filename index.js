var sodium = require('sodium').api
var pull = require('pull-stream')

var Handshake = require('./handshake')
var State = require('./state')

var challenge_length = 64
var client_auth_length = 16+32+64
var server_auth_length = 16+64
var mac_length = 16

//client is Alice
//create the client stream with the public key you expect to connect to.
exports.client =
exports.createClientStream = function (alice, app_key) {

  return function (bob_pub, cb) {
    var state = new State(app_key, alice, bob_pub)

    var stream = Handshake(cb)
    var shake = stream.handshake
    delete stream.handshake

    shake.write(state.createChallenge())

    shake.read(challenge_length, function (err, msg) {
      //create the challenge first, because we need to generate a local key
      if(!state.verifyChallenge(msg))
        return shake.abort(new Error('wrong protocol (version?)'), cb)

      shake.write(state.createClientAuth())

      shake.read(server_auth_length, function (err, boxed_sig) {
        if(!state.verifyServerAccept(boxed_sig))
          return shake.abort(new Error('server not authenticated'), cb)

        cb(null, shake.rest(), state.cleanSecrets())
      })
    })

    return stream
  }
}

//server is Bob.
exports.server =
exports.createServerStream = function (bob, authorize, app_key) {

  return function (cb) {
    var state = new State(app_key, bob)
    var stream = Handshake(cb)

    var shake = stream.handshake
    delete stream.handshake

    shake.read(challenge_length, function (err, challenge) {
      if(!state.verifyChallenge(challenge))
        return shake.abort(new Error('wrong protocol/version'), cb)

      shake.write(state.createChallenge())
      shake.read(client_auth_length, function (err, hello) {
        if(!state.verifyClientAuth(hello))
          return shake.abort(new Error('unauthenticated client'), cb)

        //check if the user wants to speak to alice.
        authorize(state.remote.public, function (err) {
          if(err) return shake.abort(err, cb)
          shake.write(state.createServerAccept())
          cb(null, shake.rest(), state.cleanSecrets())
        })
      })
    })
    return stream
  }
}

