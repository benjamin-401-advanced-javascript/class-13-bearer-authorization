'use strict';

const User = require('./users-model.js');

module.exports.authKey = (req, res, next) => {
  req.authKey = true;
  next();
}

module.exports.auth = (req, res, next) => {

  try {
    let [authType, authString] = req.headers.authorization.split(/\s+/);

    switch (authType.toLowerCase()) {
      case 'basic':
        return _authBasic(authString);
      case 'bearer':
        return _authBearer(authString);
      default:
        return _authError();
    }
  }
  catch (e) {
    next(e);
  }


  function _authBasic(str) {
    // str: am9objpqb2hubnk=
    let base64Buffer = Buffer.from(str, 'base64'); // <Buffer 01 02 ...>
    let bufferString = base64Buffer.toString();    // john:mysecret
    let [username, password] = bufferString.split(':'); // john='john'; mysecret='mysecret']
    let auth = { username, password }; // { username:'john', password:'mysecret' }

    return User.authenticateBasic(auth)
      .then(user => _authenticate(user))
      .catch(next);
  }

  function _authBearer(authToken) {
    return User.authenticateToken(authToken, req.authKey)
      .then(user => _authenticate(user, authToken))
      .catch(next);
  }

  function _authenticate(user, authToken) {
    // add user and token to req if user exists
    if (user) {
      req.user = user;
      // if authKey has been set to true (happens in middleware authKey method)
      // return the same token
      if (req.authKey) {
        req.token = authToken;
      } else {
        // else generate new token
        req.token = user.generateToken();
      }
      next();
    }
    else {
      _authError();
    }
  }

  function _authError() {
    next('Invalid User ID/Password');
  }

};