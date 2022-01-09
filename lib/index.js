"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var AuthenticationController = (function () {
  function AuthenticationController(log, login, cookie, decrypt) {
    this.log = log;
    this.login = login;
    this.cookie = cookie;
    this.decrypt = decrypt;
    this.authenticate = this.authenticate.bind(this);
  }
  AuthenticationController.prototype.authenticate = function (req, res) {
    var _this = this;
    var user = req.body;
    if (!user.username || user.username.length === 0 || !user.password || user.password.length === 0) {
      res.status(401).end('username and password cannot be empty');
    }
    if (this.decrypt) {
      var p = this.decrypt(user.password);
      if (p === undefined) {
        return res.status(401).end('cannot decrypt password');
      }
      else {
        user.password = p;
      }
    }
    this.login(user).then(function (r) {
      var account = r.user;
      if (_this.cookie && account && account.token && account.tokenExpiredTime) {
        res.status(200).cookie('token', account.token, {
          sameSite: 'strict',
          path: '/',
          expires: account.tokenExpiredTime,
          httpOnly: true,
          secure: true,
        }).json(r).end();
      }
      else {
        res.status(200).json(r).end();
      }
    }).catch(function (err) { return handleError(err, res, _this.log); });
  };
  return AuthenticationController;
}());
exports.AuthenticationController = AuthenticationController;
exports.AuthenticationHandler = AuthenticationController;
var PrivilegeController = (function () {
  function PrivilegeController(log, privileges) {
    this.log = log;
    this.privileges = privileges;
    this.all = this.all.bind(this);
  }
  PrivilegeController.prototype.all = function (req, res) {
    var _this = this;
    this.privileges().then(function (r) {
      res.json(r).end();
    }).catch(function (err) { return handleError(err, res, _this.log); });
  };
  return PrivilegeController;
}());
exports.PrivilegeController = PrivilegeController;
exports.PrivilegesController = PrivilegeController;
exports.PrivilegeHandler = PrivilegeController;
exports.PrivilegesHandler = PrivilegeController;
function handleError(err, res, log) {
  if (log) {
    log(toString(err));
    res.status(500).end('Internal Server Error');
  }
  else {
    res.status(500).end(toString(err));
  }
}
exports.handleError = handleError;
function toString(v) {
  return typeof v === 'string' ? v : JSON.stringify(v);
}
exports.toString = toString;
