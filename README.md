# secret-handshake

secure-channel based on a a mutually authenticating key agreement handshake, with forward secure identity metadata.

For a full explanation of the design, read the
[Design Paper](http://dominictarr.github.io/secret-handshake-paper/shs.pdf)

## Implementations

* javascript/node.js this repo.
* go [cryptix/secretstream](https://github.com/cryptix/secretstream/)
* rust [AljoschaMeyer/secret-handshake-rs](https://github.com/AljoschaMeyer/secret-handshake-rs)
* c [AljoschaMeyer/shs1-c](https://github.com/AljoschaMeyer/shs1-c) (actually just implements the crypto, not the protocol used as a component in the rust implementation)
* python/twisted [david415/txsecrethandshake](https://github.com/david415/txsecrethandshake) (WIP)
* C [Kodest/cshs](https://github.com/Kodest/cshs)
* C++ [Kodest/cppshs](https://github.com/Kodest/cppshs) (WIP)
* also [keks/tamarin-shs](https://github.com/keks/tamarin-shs) is a formal proof of the cryptographic properties!

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

``` js
var SHS = require('secret-handshake')

var cl = require('chloride')
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

//simulate a streaming network connection by connecting streams together
pull(alice_stream, bob_stream, alice_stream)
```

## Notes

I recommend using secret-handshake via [multiserver](https://github.com/dominictarr/multiserver)

[pull-streams](https://github.com/dominictarr/pull-streams) are used.
Learn about how pull-streams from [these examples](https://github.com/dominictarr/pull-stream-examples)

Keypairs are expected to be of the form [sodium](https://github.com/paixaop/node-sodium) produces.
[chloride](https://github.com/dominictarr/chloride) is my fork of this and is compatible.

If you're interested in the protocol, you can read more here : https://ssbc.github.io/scuttlebutt-protocol-guide/#handshake

## api

### createClient(keypair, authorize, appkey, timeout) => createClientStream(key, seed?, cb(err, plainstream)) => cipherstream

`createClient` takes: 
- `keypair` - a keypair of form `{ secretKey, publicKey }` (see `chloride#crypto_sign_keypair`)
- `appkey` - the network identifier, 32 random bytes
- `timeout` - an integer (in milliseconds? CHECK THIS)

and returns a `createClientStream`

`createClientStream` takes a the public `key` for the remote peer,
an optional `seed` (which is used to generate a one-time private key),
and a callback, `cb`. `cipherstream`, an encrypted duplex pull-stream is returned.

Once the stream is connected to a server stream,
secret-handshake will attempt to authorize, and will call
`cb` with an `err` if it fails, or `plainstream` if it succeeds.
If `keypair` is null, `seed` *must* be provided.

### createServer(keypair, authorize(id, cb), appkey, timeout) => createServerStream(cb(err, plain_stream)) => cipherstream

`createServer` is similar, except it takes `authorize`,
- `keypair` - a keypair of form `{ secretKey, publicKey }` (see `chloride#crypto_sign_keypair`)
- `authorize` - an async function of signature `(id, cb)` that decides whether a client with id == publicKey is allowed to continue with handshake
- `appkey` - the network identifier, 32 random bytes
- `timeout` - an integer (in milliseconds? CHECK THIS)

A stream constructor function is returned
Note the server DOES NOT take the client id as an argument - instead, in the process
of the handshake, the server learns the `id`, and passes it to `authorize`.
If `authorize` calls back truthy, then it will callback `cb(null, plainstream)`
else it errors, `cb(err)`.
The value that `authorize` calls back `cb(null, <V>)` will be assigned to `plainstream.auth = <V>`.
Also, the `id` of the remote will be assigned to `plainstream.id`.
This way the application layer can know who it's peer is.

## License

MIT
