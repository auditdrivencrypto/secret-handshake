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

[chloride](https://github.com/dominictarr/chloride) is required to generate
key pairs. (which is my fork of) [sodium](https://github.com/paixaop/node-sodium) (which is also compatible)


``` js
var SHS = require('secret-handshake')

var cl = require('chloride').api
var appKey = ... //32 random bytes
var alice = cl.crypto_sign_keypair() //client
var bob = cl.crypto_sign_keypair()   //server

function authorize(id, cb) {
  cb(null, check(id)) //check wether id is authorized.
}

//initialize, with default timeouts.
var ServerStream = SHS.createServer(alice, authorize, appKey)
var ClientStream = SHS.createClient(bob, appkey)

var alice_stream = ServerStream(function (err, stream) {
  ...
})

var bob_stream = ClientStream(alice.publicKey, function (err, stream) {
  ...
})

//connect streams together.
pull(alice_stream, bob_stream, alice_stream)
```

I recommend using secret-handshake via [multiserver](https://github.com/dominictarr/multiserver)

## api

### createClient(keypair, appkey, timeout) => createClientStream(key, seed?, cb(err, plainstream)) => cipherstream

`createClient` takes `keypair` `appkey` and `timeout` and
returns a `createClientStream`

`createClientStream` takes a the public `key` for the remote peer,
an optional `seed` (which is used to generate a one-time private key),
and a callback, `cb`. `cipherstream`, an encrypted duplex pull-stream is returned.

Once the stream is connected to a server stream,
secret-handshake will attempt to authorize, and will call
`cb` with an `err` if it fails, or `plainstream` if it succeeds.
If `keypair` is null, `seed` *must* be provided.

### createServer(keypair, authorize(id, cb), appkey, timeout) => createServerStream(cb(err, plain_stream)) => cipherstream

`createServer` is similar, except it takes `authorize`,
which is an async function that will be called when a client connects.
A stream constructor function is returned, but the server does
take the client id as an argument. Instead, in the process
of the handshake, the server learns the `id`, and passes it to
`authorize`. If `authorize` calls back truthy,
then it will callback `cb(null, plainstream)` else it errors,
`cb(err)`. The value that `authorize` calls back `cb(null, <V>)`
will be assigned to `plainstream.auth = <V>`. Also,
the `id` of the remote will be assigned to `plainstream.id`.
This way the application layer can know who it's peer is.


build a client constructor. `keypair` may be null,
if the stream will be used

## License

MIT


