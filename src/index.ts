import { Request, Response } from "express"
import { JsonWebTokenError, sign, TokenExpiredError, verify } from "jsonwebtoken"

export interface User {
  step?: number
  username: string
  password: string
  passcode?: string
  ip?: string
  device?: string
}
export interface Result {
  status: number | string
  user?: Account
  message?: string
  token?: string
}
export interface Account {
  id?: string
  username?: string
  contact?: string
  email?: string
  phone?: string
  displayName?: string
  passwordExpiredTime?: Date
  roles?: string[]
  privileges?: Privilege[]
  language?: string
  dateFormat?: string
  timeFormat?: string
  gender?: string
  imageURL?: string
}
export type UserAccount = Account
export interface Privilege {
  id?: string
  name: string
  resource?: string
  path?: string
  icon?: string
  sequence?: number
  children?: Privilege[]
  permissions?: number
}

export type Log = (msg: string) => void
export interface StringMap {
  [key: string]: string
}
export class AuthenticationController<T extends User> {
  constructor(
    protected login: (user: T) => Promise<Result>,
    protected log: Log,
    protected accessToken: string,
    protected accessSecret: string,
    protected expiresIn: number,
    protected sameSite: "lax" | "strict" | "none",
    protected payloadMap: StringMap,
    protected rememberToken?: string,
    protected rememberSecret?: string,
    protected rememberExpiresIn?: number,
    protected cookie?: boolean,
    protected decrypt?: (cipherText: string) => string | undefined,
  ) {
    this.authenticate = this.authenticate.bind(this)
  }
  authenticate(req: Request, res: Response) {
    const user: T = req.body
    if (!user.username || user.username.length === 0) {
      return res.status(401).end("username cannot be empty")
    }
    if (!user.password || user.password.length === 0) {
      return res.status(401).end("password cannot be empty")
    }
    if (user.step && user.step > 1 && (!user.passcode || user.passcode.length === 0)) {
      return res.status(401).end("passcode cannot be empty")
    }
    if (this.decrypt) {
      const p = this.decrypt(user.password)
      if (p === undefined) {
        return res.status(401).end("cannot decrypt password")
      } else {
        user.password = p
      }
    }
    this.login(user)
      .then((r) => {
        const account = r.user
        if (account) {
          if (!account.displayName) {
            account.displayName = account.username ? account.username : account.email ? account.email : account.id
          }
          const payload = map(account, this.payloadMap)
          const token = sign(payload, this.accessSecret, {
            expiresIn: this.expiresIn,
          })
          if (this.cookie && this.accessToken) {
            res.cookie(this.accessToken, token, { path: "/", httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn })
            if (this.rememberToken && this.rememberSecret && this.rememberExpiresIn && this.rememberExpiresIn > 0) {
              const rememberToken = sign(payload, this.rememberSecret, { expiresIn: this.rememberExpiresIn })
              res.cookie(this.rememberToken, rememberToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.rememberExpiresIn })
            }
          } else {
            r.token = token
          }
          res.status(200).json(r).end()
        } else {
          res.status(200).json(r).end()
        }
      })
      .catch((err) => handleError(err, res, this.log))
  }
}

// use to map payload for JWT
export function map<T>(obj: T, m?: StringMap): any {
  if (!m) {
    return obj
  }
  const mkeys = Object.keys(m)
  if (mkeys.length === 0) {
    return obj
  }
  const obj2: any = {}
  const keys = Object.keys(m as any)
  for (const key of keys) {
    let k0 = m[key]
    if (!k0) {
      k0 = key
    }
    const v = (obj as any)[key]
    if (v !== undefined) {
      obj2[k0] = v
    }
  }
  return obj2
}
export const AuthenticationHandler = AuthenticationController

// tslint:disable-next-line:max-classes-per-file
export class PrivilegeController {
  constructor(
    protected privileges: () => Promise<Privilege[]>,
    protected log: Log,
  ) {
    this.all = this.all.bind(this)
  }
  all(req: Request, res: Response) {
    this.privileges()
      .then((r) => res.json(r).end())
      .catch((err) => handleError(err, res, this.log))
  }
}
export const PrivilegeHandler = PrivilegeController

export class TokenController {
  constructor(
    protected accessToken: string,
    protected accessSecret: string,
    protected expiresIn: number,
    protected sameSite: "lax" | "strict" | "none",
    protected rememberToken: string,
    protected rememberSecret: string,
    protected log: Log,
  ) {
    this.refresh = this.refresh.bind(this)
  }
  refresh(req: Request, res: Response) {
    let rememberToken: string | undefined = req.cookies[this.rememberToken]
    if (!rememberToken) {
      res.status(401).end("the remember token does not exist")
    } else {
      verify(rememberToken, this.rememberSecret, (err: any, decoded: any) => {
        if (err) {
          if (err instanceof TokenExpiredError) {
            res.status(401).end("the remember token is expired")
          } else if (err instanceof JsonWebTokenError) {
            res.status(401).end("invalid remember token")
          } else {
            if (this.log) {
              this.log("Internal Server Error " + toString(err))
            }
            res.status(500).end("Internal Server Error")
          }
        } else {
          removeJWTFields(decoded)
          const newToken = sign(decoded, this.accessSecret, { expiresIn: this.expiresIn })
          res.cookie(this.accessToken, newToken, { httpOnly: true, secure: true, sameSite: this.sameSite, maxAge: this.expiresIn })
          res.status(200).end("refresh token successfully")
        }
      })
    }
  }
}
export const TokenHandler = TokenController
export function removeJWTFields(obj: any) {
  delete obj.iat
  delete obj.exp
}

export function handleError(err: any, res: Response, log?: (msg: string) => void) {
  if (log) {
    log(toString(err))
    res.status(500).end("Internal Server Error")
  } else {
    res.status(500).end(toString(err))
  }
}
export function toString(v: any): string {
  return typeof v === "string" ? v : JSON.stringify(v)
}
