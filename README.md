# secure-handshake



```
Alice                       |  Bob
----------------------------+----------------------------
[cv25519 a] ->              |
                            |  <- [cv25519 b]
key = shared(a, b)          |  key = shared(a, b)
[                           |
  box(                      |
    hi =
    alice.pub               |
    + sign(bob.pub          |
      + hash(key)),         |
    key                     |
  )                         |
]  ->                       |
                            | verify(sig, bob.pub + hash(key), alice.pub)
                            |--server is authed ----
                            | authenticate(alice.pub)
                            | <- [box(sign(hi + hash(key)), key)]
verify(sig, hi, bob.pub)    |
--client is authed----------|

```

```
-Alice-----------------------

ax = keypair()

ax ->

------------------------Bob-
               -> ax

                bx = keypair()
                key = shared(ax, bx)

                <- bx
-Alice-----------------------
-> bx

key = shared(bx, ax)
key2 = hash(key + shared(a, bob))
//double keyed, so that client identity is forward secure.
//since this depends on bob's key too, alice reveals her identity
//only to bob.
box(
  hi = [alice.pub, sign([bob.pub, hash(key)])],
  key2
) -> // (16+32+64=112 bytes)
------------------------Bob-
                -> boxed

                key2 = hash(key + shared(ax, bob))
                hi = unbox(boxed, key2))

                //unpack values out of hi.
                [alice.pub, ax2, sig] = hi

                verify(sig, [bob.pub, ax2, hash(key)], alice.pub)

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

## Client hello

### Simplest.

The simplest client hello would just be to send Alice's public key,
and to sign bob's key + the challenges (or hash(secret))

This would prove the client's identity, but Eve will know the client's
public key.

### Better

boxing the client hello with the shared secret would mean that
Eve could not know the client identity, but Mallory (the man in the middle) 
would. The handshake would error - but mallory would still
learn the client public key.

So, instead, box twice. derive another shared key between
alice's key exchange, and bob's long term key, and then box _that_
with the shared key, so that the client identity is forward secure.

you could double box, or you could double key.

box(box(msg, shared(a, bob), shared(a, b))

OR

box(msg, hash(shared(a, bob), shared(a, b))

(a & b are temp keys, bob & alice are long term keys)

hmm single box seems simpler. is a hash faster than a scalarmult?

way faster.

## License

MIT
