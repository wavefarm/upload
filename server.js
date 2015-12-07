var crypto = require('crypto');
var fs = require('fs');
var http = require('http');
var moment = require('moment');
var mustache = require('mustache');

var port = process.env.PORT || 1042
var template = fs.readFileSync('index.html', 'utf8');

http.createServer(function (req, res) {
  var acl = 'public-read';
  var bucket = process.env.BUCKET;
  var successActionRedirect = process.env.LOCATION;
  var policyDoc = {
    expiration: moment().add(10, 'minutes').utc().format('YYYY-MM-DDTHH:mm:ss\\Z'),
    conditions: [
      {acl: acl},
      {bucket: bucket},
      {success_action_redirect: successActionRedirect},
      ['starts-with', '$key', ''],
      ['starts-with', '$Content-Type', '']
    ]
  };
  var policy = new Buffer(JSON.stringify(policyDoc)).toString('base64');

  var hmac = crypto.createHmac('sha1', process.env.SECRET_KEY);
  hmac.update(policy);

  var view = {
    path: moment().format('YYYYMMDDHHmmss'),
    accessKey: process.env.ACCESS_KEY,
    bucket: bucket,
    acl: acl,
    successActionRedirect: successActionRedirect,
    policy: policy,
    signature: hmac.digest('base64')
  };
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(mustache.render(template, view));
}).listen(port, function () {
  console.log('Listening on port', port)
  if (process.send) process.send('online')
});
