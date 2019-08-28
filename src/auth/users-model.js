'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// TOKEN_LIFE can be 'one-use' or 'expires'
const TOKEN_LIFE = 'expires';

const users = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  role: { type: String, default: 'user', enum: ['admin', 'editor', 'user'] },
});

users.pre('save', function (next) {
  bcrypt.hash(this.password, 10)
    .then(hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch(console.error);
});

users.statics.createFromOauth = function (email) {

  if (!email) { return Promise.reject('Validation Error'); }

  return this.findOne({ email })
    .then(user => {
      if (!user) { throw new Error('User Not Found'); }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch(error => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({ username, password, email });
    });

};

users.statics.disabledTokens = {
}

users.statics.authenticateToken = function (token) {
  // if TOKEN_LIFE is 'one-use' 
  if (TOKEN_LIFE === 'one-use') {
    // if token is in disabled return error
    if (this.disabledTokens[token]) {
      return 'Token has be disabled'
    } else { // if toke is not disabled yet add it to disabled.
      this.disabledTokens[token] = 1;
    }
  }
  // get back what we had before encryption {_id:_id, role:role}
  let parsedToken = jwt.verify(token, process.env.SECRET);
  // create a query object to query our database for user
  let query = { _id: parsedToken.id };
  // query database and return user
  return this.findOne(query);
};

users.statics.authenticateBasic = function (auth) {
  let query = { username: auth.username };
  return this.findOne(query)
    .then(user => user && user.comparePassword(auth.password))
    .catch(error => { throw error; });
};

users.methods.comparePassword = function (password) {
  return bcrypt.compare(password, this.password)
    .then(valid => valid ? this : null);
};

users.methods.generateToken = function () {

  let token = {
    id: this._id,
    role: this.role,
  };


  switch (TOKEN_LIFE) {
    case 'expires':
      return jwt.sign(token, process.env.SECRET, { expiresIn: '1h' });
    case 'one-use':
      return jwt.sign(token, process.env.SECRET);
    default:
      return 'TOKEN_LIFE environment variable not set properly';
  }
};

module.exports = mongoose.model('users', users);
