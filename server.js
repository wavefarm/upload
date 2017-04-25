var crypto = require('crypto');
var fs = require('fs');
var http = require('http');
var moment = require('moment');
var mustache = require('mustache');
var nodemailer = require('nodemailer');
var url = require('url');

var port = process.env.PORT || 1042;
var template = fs.readFileSync('index.html', 'utf8');
var transporter = nodemailer.createTransport({
  service: process.env.SMTP_SERVICE,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});
// 20170425 - 0.0.0
http.createServer(function (req, res) {
  var acl = 'public-read';
  var bucket = process.env.BUCKET;
  var successActionRedirect = process.env.LOCATION;
  var policyDoc = {
    expiration: moment().add(60, 'minutes').utc().format('YYYY-MM-DDTHH:mm:ss\\Z'),
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

  // Mail admins on get with key param
  var query = url.parse(req.url, true).query;
  var fileUrl = query && query.key && 'https://data.wavefarm.org/' + query.key;

  if (fileUrl) {
    var opt = {
      from: 'Wave Farm <info@wavefarm.org>',
      subject: 'Wave Farm upload',
      to: 'info@wgxc.org,archive@wgxc.org,info@wavefarm.org',
      text: 'A file has been uploaded to data.wavefarm.org.\n\nURL: ' + fileUrl + '\n'
    };

    transporter.sendMail(opt, function (err, info) {
      if (err) return console.error(err)
      console.log('Email sent: ' + info.response)
    });
  }

  var view = {
    path: moment().format('YYYYMMDDHHmmss'),
    accessKey: process.env.ACCESS_KEY,
    bucket: bucket,
    acl: acl,
    successActionRedirect: successActionRedirect,
    policy: policy,
    signature: hmac.digest('base64'),
    url: fileUrl
  };

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(mustache.render(template, view));
}).listen(port, function () {
  console.log('Listening on port', port)
  if (process.send) process.send('online')
});
