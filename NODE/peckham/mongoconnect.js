var Db = require('mongodb').Db;
var Connection = require('mongodb').Connection;
var Server = require('mongodb').Server;
var BSON = require('mongodb').BSON;
var ObjectID = require('mongodb').ObjectID;

Locations = function(host, port) {
  this.db= new Db('3d', new Server(host, port, {auto_reconnect: true}, {}));
  this.db.open(function(){});
};

Locations.prototype.getCollection= function(callback) {
  this.db.collection('rawdata', function(error, Locations) {
    if( error ) callback(error);
    else callback(null, Locations);
  });
};

Locations.prototype.findAll = function(callback) {
    this.getCollection(function(error, Locations) {
      if( error ) callback(error)
      else {
        Locations.find({'MAC': '58:b0:35:83:20:79'}).limit(1).sort('_id','-1').toArray(function(error, results) {
          if( error ) callback(error)
          else callback(null, results)
        });
      }
    });
};
exports.Locations = Locations;
