# simple-keystone-client

This library provides the minimal useful Keystone identity client in a small, clean, well-tested package.

## Installation

```
npm install simple-keystone-client
```

## API

First, get the client library in your Node.js or IO.js script.

```js
var client = require('simple-keystone-client');
```

### client.authenticate(options, cb)

Authenticates and returns an access response to the callback. `options` is a
hash containing the following keys:

- `username` - REQUIRED The username to log in as.
- `apiKey` - The API key to use. If it is not supplied, a password must be used instead.
- `password` - The password to use. If it is not supplied, an API key must be present.
- `identityEndpoint` - The identity endpoint to use, defaults to `https://identity.api.rackspacecloud.com/v2.0/tokens`
- `tenantId` - An optional tenant ID. This helps some Keystone implementations generate correct endpoints for services in the catalog.

The callback takes two arguments `(err, res)` where `err` is the error that
occurred, if any, and `res.access` is the access from Keystone containing an
access token and a service catalog.
