'use strict';

var client = require('../lib/client'),
  expect = require('chai').expect,
  nock = require('nock');

function noop () {}

describe('client.authenticate', function () {
  it('gets the service catalog from the identity endpoint', function (done) {
    var scope = nock('https://identity.api.rackspacecloud.com')
      .post('/v2.0/tokens', {
        auth: {
          'RAX-KSKEY:apiKeyCredentials': {
            username: 'test.user',
            apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef'
          }
        }
      })
      .reply(200, { access: { token: 'WOOO!' } });

    client.authenticate({
      username: 'test.user',
      apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef'
    }, function (err, catalog) {
      if (err) {
        return done(err);
      }
      scope.done();
      expect(catalog).to.exist();
      done();
    });
  });

  it('allows password authentication', function (done) {
    var scope = nock('https://identity.api.rackspacecloud.com')
      .post('/v2.0/tokens', {
        auth: {
          passwordCredentials: {
            username: 'test.user',
            password: 'secretlol'
          }
        }
      })
      .reply(200, { access: { token: 'WOOO!' } });

    client.authenticate({
      username: 'test.user',
      password: 'secretlol'
    }, function (err) {
      if (err) {
        return done(err);
      }
      scope.done();
      done();
    });
  });

  it('uses the configured identity endpoint', function (done) {
    var scope;

    scope = nock('http://localhost:8900')
      .post('/identity/v2.0/tokens')
      .reply(200, { access: { token: 'WOOO!' } });

    client.authenticate({
      identityEndpoint: 'http://localhost:8900/identity/v2.0/tokens',
      username: 'test.user',
      apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef'
    }, function (err, catalog) {
      if (err) {
        return done(err);
      }
      scope.done();
      expect(catalog).to.exist();
      done();
    });
  });

  it('sends the tenant id if present', function (done) {
    var scope;

    scope = nock('https://identity.api.rackspacecloud.com')
      .post('/v2.0/tokens', {
        auth: {
          'RAX-KSKEY:apiKeyCredentials': {
            username: 'test.user',
            apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef'
          },
          tenantId: '123456'
        }
      })
      .reply(200, { access: { token: 'WOOO!' } });

    client.authenticate({
      username: 'test.user',
      apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef',
      tenantId: '123456'
    }, function (err) {
      if (err) {
        return done(err);
      }
      scope.done();
      done();
    });
  });

  it('sends the tenantName if present', function (done) {
    var scope;

    scope = nock('https://identity.api.rackspacecloud.com')
      .post('/v2.0/tokens', {
        auth: {
          'RAX-KSKEY:apiKeyCredentials': {
            username: 'test.user',
            apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef'
          },
          tenantName: 'foobar'
        }
      })
      .reply(200, { access: { token: 'WOOO!' } });

    client.authenticate({
      username: 'test.user',
      apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef',
      tenantName: 'foobar'
    }, function (err) {
      if (err) {
        return done(err);
      }
      scope.done();
      done();
    });
  });

  it('throws an error when both tenant id and tenant name are supplied',
    function () {
      expect(function () {
        client.authenticate({
        username: 'test.user',
        apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef',
        tenantName: 'foobar',
        tenantId: '123456'
      }, noop);
      }).to.throw('[simple-keystone-client:badoptions] TenantName' +
        'and tenantId cannot be specified together.');
    }
  );

  it('propagates authentication failures', function (done) {
    var scope = nock('https://identity.api.rackspacecloud.com')
      .post('/v2.0/tokens')
      .reply(401, { unauthorized: { code: 401, message: 'Oops!' } });

    client.authenticate({
      username: 'test.user',
      apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef'
    }, function (err) {
      scope.done();
      expect(err.message).to.equal('(401)[simple-keystone-client:unauth] Oops!');
      done();
    });
  });

  it('throws an error when a username is not supplied', function () {
    expect(function () {
      client.authenticate({ password: 'lolyou' }, noop);
    }).to.throw('[simple-keystone-client:nouser] Authentication requires ' +
      'a username!');
  });

  it('throws an error when neither a password nor an API key are supplied',
    function () {
      expect(function () {
        client.authenticate({ username: 'nopassword' }, noop);
      }).to.throw('[simple-keystone-client:nocreds] Either a password or an ' +
        'API key is required!');
    }
  );

  it('returns an error to the callback when the response is malformed', function (done) {
    var scope;

    scope = nock('https://identity.api.rackspacecloud.com')
      .post('/v2.0/tokens')
      .reply(200, { whatsthis: 'idunno' });

    client.authenticate({
      username: 'test.user',
      apiKey: 'deadbeefdeadbeefdeadbeefdeadbeef'
    }, function (err) {
      scope.done();
      expect(err.message).to.match(/^\[simple\-keystone\-client:malformed\]/);
      done();
    });
  });
});
