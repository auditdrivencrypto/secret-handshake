# secret-handshake

A mutually authenticating key agreement handshake, with forward secure identity metadata.

## Claims

This protocol derives shared keys and mutually
authenticate both ends of the connection.
The shared keys are forward secure, and
the identity metadata is _also forward secure_.

by "forward secure identity metadata" I mean:

* a later key compromise cannot confirm the public keys in the handshake.

And also:

* an eavesdropper cannot learn public keys
* replay attacker cannot learn public keys.
* man in the middle cannot learn public keys.
* a "wrong number" cannot learn public keys.
* an unauthenticated client cannot learn server key.
  
> note: a wrong number is just an accidental man in the middle.
> since an unauthenticated client cannot confirm the server key
> then cold calling / war dialing is not possible.

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

## Pseudocode

Note, if any calls to `unbox`, `verify`, or `authenticate` fail,
then the handshake is aborted.

```
-Alice-----------------------

ax = keypair()

ax.publicKey ->

------------------------Bob-
               -> ax.publicKey

                bx = keypair()
                key = shared(ax, bx)

                <- bx.publicKey
-Alice-----------------------
-> bx.publicKey

key = shared(bx, ax)
key2 = hash(key + shared(a, bob))
//double keyed, so that client identity is forward secure.
//since this depends on bob's key too, alice reveals her identity
//only to bob.

//alice signs bob's public key, which proves
//she intended to call him.
box(
  hi = [alice.pub, sign([bob.pub, hash(key)])],
  key2
) -> // (16+32+64=112 bytes)
------------------------Bob-
                -> boxed

                key2 = hash(key + shared(ax, bob))
                hi = unbox(boxed, key2))

                //unpack values out of hi.
                [alice.pub, sig] = hi

                verify(sig, [bob.pub, hash(key)], alice.pub)

                *** a man in the middle attack fails here ***

                *** (server is authed) ***

                  //ask user whether they want to talk to alice.
                authenticate(alice)

                key3 = hash(key2 + shared(alice, bx))

                <- box(sign([hi, hash(key)]), key3)) //64 bytes
-Alice-----------------------
<- boxed2
hi2 = unbox(boxed2, hash(key + shared(bx, alice)))
verify(hi2.sig, [hi, hash(key)], bob.pub)

*** (client is authed) ***
```

## Why

I took the simplest, most obvious design and adjusted it until
it became as private as possible.

### Simplest.

The simplest design would just be to send Alice's public key,
and to sign bob's key + the key exchanges (or hash(secret))

This would prove the Alice's identity, and that she intended to call Bob,
but Eve can learn the client's public key.

### Better

boxing the client hello with the shared secret would mean that
Eve could not know the client identity, but Mallory (the man in the middle) 
would. The handshake would error - but mallory would still
learn the client public key.

### Best

So, instead, key twice! Send Bob a confirmation that only he can open.
Bob does not yet know it's Alice, so we cannot use Alice's key,
but we can use a key derived from Alice's temporary key with Bob's
long term key. Only bob can open this message, so only Bob
can learn it is Alice trying to contact him.

Then Bob would confirm his identity to Alice by signing her
confirmation (proving he opened it) and then boxing that back to her,
but extending the key the same way that Alice did.

## Design Avoidances

There are several things that this protocol specifically doesn't do,
that seem to some like a good idea, and appear in other protocols.
Here is my reasoning on why I did not implement this.

### Don't encrypt the first packet.

In [curvecp](http://curvecp.org/packets.html) the first packet
is encrypted to Bob's long term key. This means that packet
can be replayed, and if Bob responds then that implies he is still
using that key. This is a privace leak because it would  confirm
that Bob has moved address.

### Don't authenticate with a shared key derived from 2 long term keys.

To derive a shared key you only need a public key, and _either_ private
key. Thus, if Bob's key has been leaked to Larry, then Larry can
create the shared key between bob and _anyone_. That means that
Larry can authenticate to Bob as anyone. This is a surprising failure
mode!

### Don't make a forgable handshake.

This one is emotional/intuitive reasoning
rather than a solid cryptographic argument.

OTR is designed to be forgable, the rationale being that
gives you plausible denyability about any connection.
I feel this is dubious at best, unless you also broadcast fake
sessions then a recorded session is likely to be authentic.
The "plausible denyability" argument would probably not standup
in a court. And if there arn't lots of falsified logs floating around,
then it seems like someone *may* be able to construct a fake
session and it will _seem real_.

This worries me a bit more than denyability, so I have avoided this
by using signatures in the authentication.

## License

MIT
