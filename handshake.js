
var Reader = require('pull-reader')
var pull = require('pull-stream')
var deferred = require('pull-defer')
var Writer = require('pull-pushable')
var cat = require('pull-cat')

module.exports = function (handshake) {

  var reader = Reader()
  var writer = Writer()

  var source = deferred.source()

  handshake({
    read: reader.read,
    write: writer.push,
    ready: function (stream) {
      writer.end()
      source.resolve(stream.source)
      pull(reader.read(), stream.sink)
    }
  })

  return {
    sink: reader,
    source: cat([writer, source])
  }
}
