var crypto = require('crypto')
var pull = require('pull-stream')
var R = new Buffer(crypto.randomBytes(16).toString('hex'), 'ascii')
var pair = require('pull-pair')
var assert = require('assert')

var handshake = require('../handshake')

function agreement (stream) {
  return handshake(function (shake) {
    shake.write(R)
    shake.read(32, function (err, data) {
      assert.deepEqual(data, R)
      shake.ready(stream)
    })
  })
}

var hello = new Buffer('hello there did it work?', 'ascii')

var client = agreement({
  source: pull.values([hello, hello, hello]),
  sink: pull.collect(function (err, data) {
    assert.deepEqual(Buffer.concat(data), 
      Buffer.concat([hello, hello, hello])
    )
    console.log('done')
  })
})

var server = agreement(pair()) //echo

function logger (name) {
  return pull.through(function (data) {
    console.log(name, data.toString('utf8'))
  })
}

pull(client, logger('A->B'), server, logger('A<-B'), client)
