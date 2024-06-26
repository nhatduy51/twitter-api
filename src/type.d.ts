import { Request } from 'express'
import User from '~/models/schemas/Users.schema'
import { TokenPayload } from './models/request/Users.requests'

declare module 'express' {
  interface Request {
    user?: User
    decoded_authorization?: TokenPayload
    decoded_refresh_token?: TokenPayload
    decoded_verify_email_token?: TokenPayload
    decoded_forgot_password_token?: TokenPayload
  }
}
