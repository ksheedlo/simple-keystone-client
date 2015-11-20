'use strict';

var request = require('request');

function authenticate(options, cb) {
  var auth, credentials;

  if (!options.username) {
    throw new Error('[simple-keystone-client:nouser] Authentication requires ' +
      'a username!');
  }

  credentials = {
    username: options.username
  };

  if (options.insecure) {
    secure = false;
  } else {
    secure = true;
  }
  
  if (options.password) {
    credentials.password = options.password;
    auth = {
      passwordCredentials: credentials
    };
  } else if (options.apiKey) {
    credentials.apiKey = options.apiKey;
    auth = {
      'RAX-KSKEY:apiKeyCredentials': credentials
    };
  } else {
    throw new Error('[simple-keystone-client:nocreds] Either a password or ' +
      'an API key is required!');
  }

  if (options.tenantId && options.tenantName) {
    throw new Error('[simple-keystone-client:badoptions] TenantName' +
        'and tenantId cannot be specified together.');
  } else if (options.tenantId) {
    auth.tenantId = options.tenantId;
  } else if (options.tenantName) {
    auth.tenantName = options.tenantName;
  }

  request({
    url: options.identityEndpoint ||
      'https://identity.api.rackspacecloud.com/v2.0/tokens',
    method: 'POST',
    headers: { accept: 'application/json' },
    body: { auth: auth },
    json: true,
    strictSSL: secure
  }, function (err, res, body) {
    if (err) {
      return cb(err);
    } else if (body.unauthorized) {
      return cb(new Error('(' + body.unauthorized.code + ')' +
        '[simple-keystone-client:unauth] ' + body.unauthorized.message));
    } else if (!body.access) {
      return cb(new Error('[simple-keystone-client:malformed] Malformed ' +
        'response: ' + JSON.stringify(body)));
    }
    cb(null, body);
  });
}

exports.authenticate = authenticate;
