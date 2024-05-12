import { Request } from 'express'
import User from '~/models/schemas/Users.schema'

declare module Request {
  interface Request {
    user?: User
  }
}
