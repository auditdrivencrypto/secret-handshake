var pull = require('pull-stream')

var Handshake = require('pull-handshake')
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

    function abort(err, reason) {
      if(err && err !== true) shake.abort(err, cb)
      else                    shake.abort(new Error(reason), cb)
    }

    shake.write(state.createChallenge())

    shake.read(challenge_length, function (err, msg) {
      if(err) return abort(err, 'challenge not accepted')
      //create the challenge first, because we need to generate a local key
      if(!state.verifyChallenge(msg))
        return abort(null, 'wrong protocol (version?)')

      shake.write(state.createClientAuth())

      shake.read(server_auth_length, function (err, boxed_sig) {
        if(err) return abort(err, 'hello not accepted')

        if(!state.verifyServerAccept(boxed_sig))
          return abort(null, 'server not authenticated')

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

    function abort (err, reason) {
      if(err && err !== true) shake.abort(err, cb)
      else                    shake.abort(new Error(reason), cb)
    }

    shake.read(challenge_length, function (err, challenge) {
      if(err) return abort(err, 'expected challenge')
      if(!state.verifyChallenge(challenge))
        return shake.abort(new Error('wrong protocol/version'))

      shake.write(state.createChallenge())
      shake.read(client_auth_length, function (err, hello) {
        if(err) return abort(err, 'expected hello')
        if(!state.verifyClientAuth(hello)) {
          //we know who the client was, but chose not to answer:
          if(state.remote.public)
            return abort(null, 'unauthenticated client:' + state.remote.public.toString('hex'), cb)
          //client dialed wrong number... (we don't know who they where)
          else
            return abort(null, 'wrong number')
        }
        //check if the user wants to speak to alice.
        authorize(state.remote.public, function (err, auth) {
          if(auth == null && !err) err = new Error('client unauthorized')
          if(!auth) return abort(err, 'client authentication rejected')
          state.auth = auth
          shake.write(state.createServerAccept())
          cb(null, shake.rest(), state.cleanSecrets())
        })
      })
    })
    return stream
  }
}

