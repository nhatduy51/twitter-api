import { Request, Response } from 'express'
import usersService from '~/services/users.services'

import { ParamsDictionary } from 'express-serve-static-core'
import { RegisterRequestBody } from '~/models/request/Users.requests'
import { ObjectId } from 'mongodb'

export const LoginController = async (req: Request, res: Response) => {
  const { user }: any = req
  const user_id = user._id as ObjectId
  const result = await usersService.login(user_id.toString())
  return res.status(200).json({
    message: 'login success',
    data: result
  })
}

export const RegisterController = async (req: Request<ParamsDictionary, any, RegisterRequestBody>, res: Response) => {
  const result = await usersService.register(req.body)
  return res.status(200).json({
    message: 'register success',
    data: result
  })
}

export const LogoutController = async () => {
  
}
