var pull = require('pull-stream')
var boxes = require('pull-box-stream')

var Handshake = require('pull-handshake')
var random = require('./random')

function isBuffer(buf, len) {
  return Buffer.isBuffer(buf) && buf.length === len
}

module.exports = function (stateless) {
  var exports = {}
  //client is Alice
  //create the client stream with the public key you expect to connect to.
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
        random: random(32)
      })

      var stream = Handshake({timeout: timeout}, cb)
      var shake = stream.handshake
      stream.handshake = null

      function abort(err, reason) {
        if(err && err !== true) shake.abort(err, cb)
        else                    shake.abort(new Error(reason), cb)
      }

      shake.write(stateless.createChallenge(state))

      shake.read(stateless.challenge_length, function (err, msg) {
        if(err) return abort(err, 'challenge not accepted')
        //create the challenge first, because we need to generate a local key
        if(!(state = stateless.clientVerifyChallenge(state, msg)))
          return abort(null, 'wrong protocol (version?)')

        shake.write(stateless.clientCreateAuth(state))

        shake.read(stateless.server_auth_length, function (err, boxed_sig) {
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
  exports.createServerStream = function (bob, authorize, app_key, timeout) {

    return function (cb) {
      var state = stateless.initialize({
        app_key: app_key,
        local: bob,
        //note, the server doesn't know the remote until it receives ClientAuth
        random: random(32)
      })
      var stream = Handshake({timeout: timeout}, cb)

      var shake = stream.handshake
      stream.handshake = null

      function abort (err, reason) {
        if(err && err !== true) shake.abort(err, cb)
        else                    shake.abort(new Error(reason), cb)
      }

      shake.read(stateless.challenge_length, function (err, challenge) {
        if(err) return abort(err, 'expected challenge')
        if(!(state = stateless.verifyChallenge(state, challenge)))
          return shake.abort(new Error('wrong protocol/version'))

        shake.write(stateless.createChallenge(state))
        shake.read(stateless.client_auth_length, function (err, hello) {
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

  //wrap the above into an actual handshake + encrypted session

  exports.toKeys = stateless.toKeys

  function secure (cb, disableEncryption) {
    return function (err, stream, state) {
      if(err) return cb(err)

      var en_nonce = state.remote.app_mac.slice(0, 24)
      var de_nonce = state.local.app_mac.slice(0, 24)

      cb(null, {
        remote: state.remote.publicKey,
        //on the server, attach any metadata gathered
        //during `authorize` call
        auth: state.auth,
        source: disableEncryption ? stream.source : pull(
          stream.source,
          boxes.createUnboxStream(state.decryptKey, de_nonce)
        ),
        sink: disableEncryption ? stream.sink : pull(
          boxes.createBoxStream(state.encryptKey, en_nonce),
          stream.sink
        )
      })
    }
  }

  exports.client =
  exports.createClient = function (alice, app_key, timeout, disableEncryption) {
    var create = exports.createClientStream(alice, app_key, timeout)

    return function (bob, seed, cb) {
      if(!isBuffer(bob, 32))
        throw new Error('createClient *must* be passed a public key')
      if('function' === typeof seed)
        return create(bob, secure(seed, disableEncryption))
      else
        return create(bob, seed, secure(cb, disableEncryption))
    }
  }

  exports.server =
  exports.createServer = function (bob, authorize, app_key, timeout, disableEncryption) {
    var create = exports.createServerStream(bob, authorize, app_key, timeout)

    return function (cb) {
      return create(secure(cb, disableEncryption))
    }
  }

  return exports
}

