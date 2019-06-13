#!/usr/bin/env node

const pull = require('pull-stream')
const toPull = require('stream-to-pull-stream')
const { createServer } = require('../..')

const appKey = Buffer.from(process.argv[2], 'hex')
const bob = { // the keypair of the server
  secretKey: Buffer.from(process.argv[3], 'hex'),
  publicKey: Buffer.from(process.argv[4], 'hex')
}
const authorize = (pubKey, cb) => cb(null, true) // all clients are allowed to connect
const timeout = 30 // I hope this is milliseconds?

const shake = createServer(bob, authorize, appKey, timeout)((err, stream) => {
  if (err) {
    log(`! ${err}`)
    // shs1-test : If the server detects that the client is not well-behaved, it must immediately exit with a non-zero exit code, without writing any further data to stdout.
    process.exit(1)
  } else {
    const { encryptKey, decryptKey, encryptNonce, decryptNonce } = stream.crypto
    const result = Buffer.concat([ encryptKey, encryptNonce, decryptKey, decryptNonce ])
    log(`< writing ${result.length} bytes (final)`)
    process.stdout.write(result)

    // process.kill(process.pid)
  }
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
  process.stderr.write(`PID ${process.pid}: ${string}\n`)
}
