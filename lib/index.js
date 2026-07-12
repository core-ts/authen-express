import { JsonWebTokenError, sign, TokenExpiredError, verify } from "jsonwebtoken";
export class AuthenticationController {
  constructor(login, log, accessToken, accessSecret, expiresIn, sameSite, payloadMap, rememberToken, rememberSecret, rememberExpiresIn, cookie, decrypt) {
    this.login = login;
    this.log = log;
    this.accessToken = accessToken;
    this.accessSecret = accessSecret;
    this.expiresIn = expiresIn;
    this.sameSite = sameSite;
    this.payloadMap = payloadMap;
    this.rememberToken = rememberToken;
    this.rememberSecret = rememberSecret;
    this.rememberExpiresIn = rememberExpiresIn;
    this.cookie = cookie;
    this.decrypt = decrypt;
    this.authenticate = this.authenticate.bind(this);
  }
  authenticate(req, res) {
    const user = req.body;
    if (!user.username || user.username.length === 0) {
      return res.status(401).end("username cannot be empty");
    }
    if (!user.password || user.password.length === 0) {
      return res.status(401).end("password cannot be empty");
    }
    if (user.step && user.step > 1 && (!user.passcode || user.passcode.length === 0)) {
      return res.status(401).end("passcode cannot be empty");
    }
    if (this.decrypt) {
      const p = this.decrypt(user.password);
      if (p === undefined) {
        return res.status(401).end("cannot decrypt password");
      }
      else {
        user.password = p;
      }
    }
    this.login(user)
      .then((r) => {
      const account = r.user;
      if (account) {
        if (!account.displayName) {
          account.displayName = account.username ? account.username : account.email ? account.email : account.id;
        }
        const payload = map(account, this.payloadMap);
        const token = sign(payload, this.accessSecret, {
          expiresIn: this.expiresIn,
        });
        if (this.cookie && this.accessToken) {
          res.cookie(this.accessToken, token, { path: "/", httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn });
          if (this.rememberToken && this.rememberSecret && this.rememberExpiresIn && this.rememberExpiresIn > 0) {
            const rememberToken = sign(payload, this.rememberSecret, { expiresIn: this.rememberExpiresIn });
            res.cookie(this.rememberToken, rememberToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.rememberExpiresIn });
          }
        }
        else {
          r.token = token;
        }
        res.status(200).json(r).end();
      }
      else {
        res.status(200).json(r).end();
      }
    })
      .catch((err) => handleError(err, res, this.log));
  }
}
// use to map payload for JWT
export function map(obj, m) {
  if (!m) {
    return obj;
  }
  const mkeys = Object.keys(m);
  if (mkeys.length === 0) {
    return obj;
  }
  const obj2 = {};
  const keys = Object.keys(m);
  for (const key of keys) {
    let k0 = m[key];
    if (!k0) {
      k0 = key;
    }
    const v = obj[key];
    if (v !== undefined) {
      obj2[k0] = v;
    }
  }
  return obj2;
}
export const AuthenticationHandler = AuthenticationController;
// tslint:disable-next-line:max-classes-per-file
export class PrivilegeController {
  constructor(privileges, log) {
    this.privileges = privileges;
    this.log = log;
    this.all = this.all.bind(this);
  }
  all(req, res) {
    this.privileges()
      .then((r) => res.json(r).end())
      .catch((err) => handleError(err, res, this.log));
  }
}
export const PrivilegeHandler = PrivilegeController;
export class TokenController {
  constructor(accessToken, accessSecret, expiresIn, sameSite, rememberToken, rememberSecret, log) {
    this.accessToken = accessToken;
    this.accessSecret = accessSecret;
    this.expiresIn = expiresIn;
    this.sameSite = sameSite;
    this.rememberToken = rememberToken;
    this.rememberSecret = rememberSecret;
    this.log = log;
    this.refresh = this.refresh.bind(this);
  }
  refresh(req, res) {
    let rememberToken = req.cookies[this.rememberToken];
    if (!rememberToken) {
      res.status(401).end("the remember token does not exist");
    }
    else {
      verify(rememberToken, this.rememberSecret, (err, decoded) => {
        if (err) {
          if (err instanceof TokenExpiredError) {
            res.status(401).end("the remember token is expired");
          }
          else if (err instanceof JsonWebTokenError) {
            res.status(401).end("invalid remember token");
          }
          else {
            if (this.log) {
              this.log("Internal Server Error " + toString(err));
            }
            res.status(500).end("Internal Server Error");
          }
        }
        else {
          removeJWTFields(decoded);
          const newToken = sign(decoded, this.accessSecret, { expiresIn: this.expiresIn });
          res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn });
          res.status(200).end("refresh token successfully");
        }
      });
    }
  }
}
export const TokenHandler = TokenController;
export function removeJWTFields(obj) {
  delete obj.iat;
  delete obj.exp;
}
export function handleError(err, res, log) {
  if (log) {
    log(toString(err));
    res.status(500).end("Internal Server Error");
  }
  else {
    res.status(500).end(toString(err));
  }
}
export function toString(v) {
  return typeof v === "string" ? v : JSON.stringify(v);
}
