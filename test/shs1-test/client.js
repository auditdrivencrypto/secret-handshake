#!/usr/bin/env node

const pull = require('pull-stream')
const toPull = require('stream-to-pull-stream')
var sodium = require('chloride')
const { createClient } = require('../..')

const alice = sodium.crypto_sign_keypair() // client
const appKey = Buffer.from(process.argv[2], 'hex')
const bobPublicKey = Buffer.from(process.argv[3], 'hex') // server
const seed = null // how do we get this fro shs1testclient ?

const timeout = 10e3 // I hope this is milliseconds!

const shake = createClient(alice, appKey, timeout)(bobPublicKey, seed, (err, stream) => {
  if (err) {
    log(`! ${err}`)
    process.exit(1)
    // shs1-test : If the server detects that the client is not well-behaved,
    // it must immediately exit with a non-zero exit code, without writing any further data to stdout.
  }

  const { encryptKey, decryptKey, encryptNonce, decryptNonce } = stream.crypto
  const result = Buffer.concat([ encryptKey, encryptNonce, decryptKey, decryptNonce ])

  log(`< writing ${result.length} bytes (final)`)
  process.stdout.write(result)
})

process.on('SIGTERM', () => {
  log('X received SIGTERM')
})

pull(
  toPull.source(process.stdin),
  pull.through(data => log(`> reading ${data.length} bytes`)),
  shake, // duplex handshake stream
  pull.through(data => log(`< writing ${data.length} bytes`)),
  toPull.sink(process.stdout)
)

function log (string) {
  // uncomment this to get some debugging data
  // process.stderr.write(`PID ${process.pid}: ${string}\n`)
}
