
var Reader = require('pull-reader')
var pull = require('pull-stream')
var deferred = require('pull-defer')
var Writer = require('pull-pushable')
var cat = require('pull-cat')
var pair = require('pull-pair')

module.exports = function (_cb) {

  var reader = Reader()
  var writer = Writer(function (err) {
    if(err) _cb(err)
  })

  var source = deferred.source()

  var p = pair()

  return {
    handshake: {
      read: reader.read,
      abort: function (err) {
        reader.abort(err, function (err) {
        })
        _cb(err)
      },
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
