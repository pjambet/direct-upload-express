
/**
 * Module dependencies.
 */

var express = require('express');
var routes = require('./routes');
var user = require('./routes/user');
var http = require('http');
var path = require('path');
var Crypto = require('crypto');
var Buffer = require('buffer').Buffer;
var uuid = require('node-uuid');

var app = express();

// all environments
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.favicon());
app.use(express.logger('dev'));
app.use(express.json());
app.use(express.urlencoded());
app.use(express.methodOverride());
app.use(express.cookieParser('your secret here'));
app.use(express.session());
app.use(app.router);
app.use(require('stylus').middleware(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

// development only
if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}


var s3UploadPolicy = function(acl, key) {
  var d = new Date();
  d.setSeconds(0);
  d.setMilliseconds(0);
  d.setMinutes(d.getMinutes() + 30);
  var policy = {
    "expiration": d.toISOString(),
    "conditions": [
      {"bucket": process.env.BUCKET_NAME},
      {"acl": acl},
      ["eq","$key", key],
      {"success_action_status": "201"}
    ]
  };
  var buf = new Buffer(JSON.stringify(policy),'utf8');
  var result = buf.toString('base64');

  return result;
};


var s3UploadSignature = function(acl, key) {
  return  Crypto.createHmac('sha1', process.env.AWS_SECRET_KEY_ID).update(s3UploadPolicy(acl, key)).digest('base64');
};


app.get('/', routes.index);
app.get('/users', user.list);
app.get('/signed_urls', function(req, res) {
  var key = "uploads/" + uuid.v4();
  var responseObject = {
    "key": key,
    "acl": 'public-read',
    "policy": s3UploadPolicy('public-read', key),
    "signature": s3UploadSignature('public-read', key)
  }
  res.send(responseObject);
});

http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});
