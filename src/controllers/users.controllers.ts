import { NextFunction, Request, Response } from 'express'
import usersService from '~/services/users.services'

import { ParamsDictionary } from 'express-serve-static-core'
import {
  ForgotPasswordRequestBody,
  LoginRequestBody,
  LogoutRequestBody,
  RegisterRequestBody,
  TokenPayload,
  VerifyForgotPasswordTokenPayload
} from '~/models/request/Users.requests'
import { ObjectId } from 'mongodb'
import databaseService from '~/services/connect.db'
import { httpStatus } from '~/constants/httpStatus'
import { USER_MESSAGES } from '~/constants/messages'
import { UserVerifyStatus } from '~/constants/enum'
import User from '~/models/schemas/Users.schema'
import { result } from 'lodash'

export const LoginController = async (req: Request<ParamsDictionary, any, LoginRequestBody>, res: Response) => {
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

export const LogoutController = async (req: Request<ParamsDictionary, any, LogoutRequestBody>, res: Response) => {
  const { refresh_token } = req.body
  const result = await usersService.logout(refresh_token)
  return res.json(result)
}

export const EmailVerifyTokenController = async (req: Request, res: Response, next: NextFunction) => {
  const { user_id } = req.decoded_verify_email_token as TokenPayload
  console.log('user_id: ', user_id)
  const user = await databaseService.users.findOne({
    _id: new ObjectId(user_id)
  })
  console.log('user: ', user)
  if (!user) {
    return res.status(httpStatus.NOT_FOUND).json({
      message: USER_MESSAGES.USER_NOT_FOUND
    })
  }
  // Đã verify rồi thì mình sẽ không báo lỗi
  // Mà mình sẽ trả về status OK với message là đã verify trước đó rồi
  if (user.email_verify_token === '') {
    return res.json({
      message: USER_MESSAGES.EMAIL_ALREADY_VERIFIED_BEFORE
    })
  }

  const result = await usersService.verifyEmail(user_id)
  return res.json({
    message: USER_MESSAGES.EMAIL_VERIFY_SUCCESS,
    result
  })
}

export const ResendEmailVerifyTokenController = async (req: Request, res: Response, next: NextFunction) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const user = await databaseService.users.findOne({
    _id: new ObjectId(user_id)
  })
  if (!user) {
    return res.status(httpStatus.NOT_FOUND).json({
      message: USER_MESSAGES.USER_NOT_FOUND
    })
  }
  if (user.verify === UserVerifyStatus.Verified) {
    return res.json({
      message: USER_MESSAGES.EMAIL_ALREADY_VERIFIED_BEFORE
    })
  }

  const result = await usersService.resendVerifyEmail(user_id)
  return res.json(result)
}

export const ForgotPasswordController = async (
  req: Request<ParamsDictionary, any, ForgotPasswordRequestBody>,
  res: Response
) => {
  const { _id } = req.user as User
  const result = await usersService.forgotPassword((_id as ObjectId).toString())
  return res.json(result)
}

export const VerifyForgotPasswordTokenController = (
  req: Request<ParamsDictionary, any, VerifyForgotPasswordTokenPayload>,
  res: Response
) => {
  return res.json({
    message: USER_MESSAGES.VERIFY_FORK_PASSWORD_SUCCESS
  })
}

export const ResetPasswordController = async (req: Request, res: Response) => {
  const { user_id } = req.decoded_forgot_password_token as TokenPayload
  const { password } = req.body
  const result = await usersService.resetPassword(user_id, password)
  return res.json(result)
}

export const getMeController = async (req: Request, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const user = await usersService.getMe(user_id)

  return res.json({
    message: USER_MESSAGES.GET_ME_SUCCESS,
    data: user
  })
}
