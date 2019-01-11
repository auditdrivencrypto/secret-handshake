//phases:
// 1 client sends challenge
// 2 server sends challenge
// 3 client sends hello (include proof they know the server)
// 4 server decides if they want client to connect with them
// 4 server sends acknowledgement to client

module.exports = {
  serverErrorOnChallenge:
    "shs.client: error when expecting server to accept challenge (phase 1).\n" +
    "possibly the server is busy, does not speak shs or uses a different application cap",

  serverInvalidChallenge:
    "shs.client: server responded with invalid challenge (phase 2). possibly server does not speak shs",

  serverHungUp:
    "shs.client: server hung up when we sent hello (phase 3).\n" +
    "Possibly we dailed a wrong number, or the server does not wish to talk to us.",

  serverAcceptInvalid:
    "shs.client: the server's response accepting us our hello (phase 5) was invalid, so we hung up",

  clientErrorOnChallenge:
    "shs.server: error when waiting for client to send challenge (phase 1)",

  clientInvalidChallenge:
    "shs.server: client sent invalid challenge (phase 1), possibly they tried to speak a different protocol or had wrong application cap",

  //we got a networking error:
  clientErrorOnHello:
    "shs.server: error when expecting client to say hello (phase 2)",

  clientInvalidHello:
    "shs.server: client hello invalid (phase 3). they dailed a wrong number - they didn't have our public key",

  clientUnauthorized:
    "shs.server: we did not authorize the client (phase 4), so we hung up.",

  serverErrorOnAuthorization:
    "shs.server: while trying to decide if the client should be authorized (phase 4), we got an error on the server. This could be a database error",
}




