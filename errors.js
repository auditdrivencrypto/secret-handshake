
module.exports = {
  serverErrorOnChallenge:
    "shs.client: error when expecting server to accept challenge.\n" +
    "possibly the server does not speak shs, or uses a different application cap",

  serverInvalidChallenge:
    "shs.client: server responded with invalid challenge. possibly server does not speak shs",

  serverHungUp:
    "shs.client: server hung up when we expected hello.\n" +
    "Possibly we dailed a wrong number, or the server does not wish to talk to us.",

  serverAcceptInvalid:
    "shs.client: the server's response accepting us was invalid, so we hung up",

  clientErrorOnChallenge:
    "shs.server: error when waiting for client to send challenge",

  clientInvalidChallenge:
    "shs.server: client sent invalid challenge, possibly they tried to speak a different protocol or had wrong application cap",

  //we got a networking error:
  clientErrorOnHello:
    "shs.server: error when expecting client to say hello",

  clientInvalidHello:
    "shs.server: client called a wrong number - they didn't have our public key",

  clientUnauthorized:
    "shs.server: we did not authorize the client, so we hung up.",

  serverErrorOnAuthorization:
    "shs.server: while trying to decide if the client should be authorized, we got an error on the server. This could be a database error",
}




