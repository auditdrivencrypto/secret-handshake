
var Reader = require('pull-reader')
var pull = require('pull-stream')
var deferred = require('pull-defer')
var Writer = require('pull-pushable')
var cat = require('pull-cat')
var pair = require('pull-pair')

module.exports = function () {

  var reader = Reader()
  var writer = Writer()

  var source = deferred.source()

  var p = pair()

  return {
    handshake: {
      read: reader.read,
      write: writer.push,
      rest: function () {
        writer.end()
        return {
          source: reader.read(),
          sink: p.sink
        }
      }
    },
    sink: reader,
    source: cat([writer, p.source])
  }
}
