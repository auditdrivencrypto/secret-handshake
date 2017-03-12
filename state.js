
var stateless = require('./stateless')

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
  return !! stateless.serverVerifyAuth.call(this, data)
}

proto.createServerAccept =
function createServerAccept () {
  return stateless.serverCreateAccept.call(this)
}

proto.verifyServerAccept =
function verifyServerAccept (boxed_okay) {
  return stateless.clientVerifyAccept.call(this, boxed_okay)
}

proto.cleanSecrets =
function cleanSecrets () {
  return stateless.clean.call(this)
}

