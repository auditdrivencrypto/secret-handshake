#!/usr/bin/env node

const pull = require('pull-stream')
const toPull = require('stream-to-pull-stream')
const { createServerStream } = require('../..')

const appKey = Buffer.from(process.argv[2], 'hex')
const bob = { // the keypair of the server
  secretKey: Buffer.from(process.argv[3], 'hex'),
  publicKey: Buffer.from(process.argv[4], 'hex')
}
const authorize = (pubKey, cb) => cb(null, true) // all clients are allowed to connect
const timeout = 30 // I hope this is milliseconds?

const ServerStream = createServerStream(bob, authorize, appKey, timeout) // duplex handshake stream
var d = Date.now()
const stream = ServerStream((err, plainStream) => {
  if (err) process.stderr.write(`X ${d} ERROR ${err}\n`)
  else process.stderr.write(`0 ${d} DONE\n`)

  process.kill(process.pid)
  // is this sufficient to kill this process? are the streams closed?
})

process.on('SIGTERM', () => {
  process.stderr.write(`X ${d} received SIGTERM\n`) // triggered by process.kill above
})

pull(
  toPull.source(process.stdin),
  pull.through(data => process.stderr.write(`> ${d}\n`)),
  stream,
  pull.through(data => process.stderr.write(`< ${d}\n`)),
  toPull.sink(process.stdout)
)
