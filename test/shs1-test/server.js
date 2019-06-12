#!/usr/bin/env node

const pull = require('pull-stream')
const toPull = require('stream-to-pull-stream')
const { createServerStream } = require('../..')

const appKey = Buffer.from(process.argv[2], 'hex')
const authorize = (pubKey, cb) => cb(null, true) // all clients are allowed to connect
const bob = { // the keypair of the server
  publicKey: Buffer.from(process.argv[4], 'hex'),
  secretKey: Buffer.from(process.argv[3], 'hex')
}
const timeout = 30 // I hope this is milliseconds?

const ServerStream = createServerStream(bob, authorize, appKey, timeout) // duplex handshake stream
const stream = ServerStream((err, plainStream) => {
  console.log(err, plainStream)
})

pull(
  toPull.source(process.stdin),
  stream,
  toPull.sink(process.stdout)
)

//
// const { verifyMsg1, createMsg2, verifyMsg3, createMsg4, serverOutcome } = require('../index.js')
// const serverState = {
//   shsStep: 1, // which message are you receiving next
//   network_identifier: Buffer.from(process.argv[2], 'hex'),
//   server_longterm_sk: Buffer.from(process.argv[3], 'hex'),
//   server_longterm_pk: Buffer.from(process.argv[4], 'hex'),
//   server_ephemeral_sk: Buffer.from([176, 248, 210, 185, 226, 76, 162, 153, 239, 144, 57, 206, 218, 97, 2, 215, 155, 5, 223, 189, 22, 28, 137, 85, 228, 233, 93, 79, 217, 203, 63, 125]),
//   server_ephemeral_pk: Buffer.from([166, 12, 63, 218, 235, 136, 61, 99, 232, 142, 165, 147, 88, 93, 79, 177, 23, 148, 129, 57, 179, 24, 192, 174, 90, 62, 40, 83, 51, 9, 97, 82])
// }

// process.stdin.on('readable', () => {
//   switch (serverState.shsStep) {
//     case 1: {
//       const msg1 = process.stdin.read()

//       if (!verifyMsg1(serverState, msg1)) process.exit(1)

//       process.stdout.write(createMsg2(serverState))
//       serverState.shsStep = 3
//       break
//     }
//     case 3: {
//       const msg3 = process.stdin.read()

//       if (!verifyMsg3(serverState, msg3)) {
//         process.exit(3)
//       }

//       const outcome = serverOutcome(serverState)
//       process.stdout.write(Buffer.concat([
//         createMsg4(serverState),
//         outcome.encryption_key,
//         outcome.encryption_nonce,
//         outcome.decryption_key,
//         outcome.decryption_nonce
//       ]))
//       break
//     }
//     default:
//   }
// })
