import { Request, Response } from 'express';

export type Log = (msg: string) => void;
export interface User {
  step?: number;
  username: string;
  password: string;
  passcode?: string;
  ip?: string;
  device?: string;
}
export type Login = User;
export type AuthInfo = User;
export interface Privilege {
  id?: string;
  name: string;
  resource?: string;
  path?: string;
  icon?: string;
  sequence?: number;
  children?: Privilege[];
  permissions?: number;
}
export interface AuthResult {
  status: number | string;
  user?: UserAccount;
  message?: string;
}
export type Result = AuthResult;
export type LoginResult = AuthResult;
export interface UserAccount {
  id?: string;
  username?: string;
  contact?: string;
  email?: string;
  phone?: string;
  displayName?: string;
  passwordExpiredTime?: Date;
  token?: string;
  tokenExpiredTime?: Date;
  newUser?: boolean;
  userType?: string;
  roles?: string[];
  privileges?: Privilege[];
  language?: string;
  dateFormat?: string;
  timeFormat?: string;
  gender?: string;
  imageURL?: string;
}
export class AuthenticationController<T extends User> {
  constructor (private log: Log, private auth: (user: T) => Promise<AuthResult>, public cookie?: boolean) {
    this.authenticate = this.authenticate.bind(this);
  }
  authenticate(req: Request, res: Response) {
    const user: T = req.body;
    if (!user.username || user.username.length === 0 || !user.password || user.password.length === 0) {
      res.status(401).end('username and password cannot be empty');
    }
    this.auth(user).then(result => {
      const account = result.user;
      if (this.cookie && account && account.token && account.tokenExpiredTime) {
        res.status(200).cookie(
          'token', account.token,
          {
            sameSite: 'strict',
            path: '/',
            expires: account.tokenExpiredTime,
            httpOnly: true,
            secure: true,
          }).json(result).end();
      } else {
        res.status(200).json(result).end();
      }
    }).catch(err => handleError(err, res, this.log));
  }
}
export const AuthenticationHandler = AuthenticationController;
export class PrivilegeController {
  constructor(private log: Log, public privileges: () => Promise<Privilege[]>) {
    this.all = this.all.bind(this);
  }
  all(req: Request, res: Response) {
    this.privileges().then(result => {
      res.json(result).end();
    }).catch(err => handleError(err, res, this.log));
  }
}
export const PrivilegesController = PrivilegeController;
export const PrivilegeHandler = PrivilegeController;
export const PrivilegesHandler = PrivilegeController;
export function handleError(err: any, res: Response, log?: (msg: string) => void) {
  if (log) {
    log(toString(err));
    res.status(500).end('Internal Server Error');
  } else {
    res.status(500).end(toString(err));
  }
}
export function toString(v: any): string {
  if (typeof v === 'string') {
    return v;
  } else {
    return JSON.stringify(v);
  }
}
