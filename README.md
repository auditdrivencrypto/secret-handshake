# secret-handshake

secure-channel based on a a mutually authenticating key agreement handshake, with forward secure identity metadata.

For a full explaination of the design, read the
[Design Paper](http://dominictarr.github.io/secret-handshake-paper/shs.pdf)

## Claims

This protocol derives shared keys and mutually
authenticates both ends of the connection.
The shared secrets are forward secure, and
so is the identity metadata.

by "forward secure identity metadata" I mean:

* a later key compromise cannot confirm the public keys in the handshake.

And also:

* an eavesdropper cannot learn public keys
* replay attacker cannot learn public keys.
* man in the middle cannot learn public keys.
* a "wrong number" cannot learn public keys.
* an unauthenticated client cannot learn server key.
  
> note: a wrong number is just an accidental man in the middle.

By "confirm" I mean check a guess at the public key.
By "learn" I mean that you can _either_ extract the public key,
or confirm the public key.

Also note that if the server decides not to authenticate a client,
it will learn their public key. To get to this stage, the client
must know the server's key, so now the client and server both
know each others key. This is fair.

## Disclaims

This protocol cannot hide your ip address.
This protocol does not attempt to obscure packet boundries.
If a man in the middle or wrong number later compromises
the server's key, they will be able to extract the client
key from the client's hello packet.

## Example

The simplest way to use secret-handshake is to use
`require('secret-handshake/net')`, a wrapper around net.
This makes it easy to create encrypted tcp connections.

[pull-streams](https://github.com/dominictarr/pull-streams) are used.
learn about how pull-streams from [these examples](https://github.com/dominictarr/pull-stream-examples)

[sodium](https://github.com/paixaop/node-sodium) is required to generate
key pairs.

``` js
var createNode = require('secret-handshake/net')
var sodium = require('sodium').api
var appKey = ... //32 random bytes
var aliceKey = sodium.crypto_sign_keypair() //client
var bobKey = sodium.crypto_sign_keypair()   //server

var alice = createNode({
  keys: aliceKey,
  appKey: appKey
})

var bob = createNode({
  keys: bobKey,
  appKey: appKey,
  //the authenticate function is required to receive calls.
  authenticate: function (pub, cb) {
    //decide whether to allow access to pub.
    if(yes) cb(null, truthy)
    else    cb(new Error('reason'))
    //The client WILL NOT see the unauthentication reason
  }
})

//now, create a server (bob) and connect a client (alice)

bob.createServer(function (stream) {
  pull(source, stream, sink)
}).listen(8978, function () {
  var stream =
    alice.connect({port: 8979, host: 'localhost', keys: bob.publicKey})

  pull(source, stream, sink)
})

```

## License

MIT
