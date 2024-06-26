import { Router } from 'express'
import {
  LoginController,
  LogoutController,
  RegisterController,
  EmailVerifyTokenController,
  ResendEmailVerifyTokenController,
  ForgotPasswordController,
  VerifyForgotPasswordTokenController,
  ResetPasswordController,
  getMeController
} from '~/controllers/users.controllers'
import {
  accessTokenValidator,
  emailVerifyTokenValidator,
  forgotPasswordValidator,
  loginValidator,
  refreshTokenValidator,
  registerValidator,
  verifyForgotPassWordTokenValidator,
  resetPasswordValidator
} from '~/middlewares/users.middlewares'
import { wrapRequestHandler } from '~/utils/handlers'

const usersRoute = Router()

usersRoute.post('/login', loginValidator, wrapRequestHandler(LoginController))
usersRoute.post('/register', registerValidator, wrapRequestHandler(RegisterController))
usersRoute.post('/logout', accessTokenValidator, refreshTokenValidator, wrapRequestHandler(LogoutController))
usersRoute.post('/email-verify', emailVerifyTokenValidator, wrapRequestHandler(EmailVerifyTokenController))
usersRoute.post('/resend-email-verify', accessTokenValidator, wrapRequestHandler(ResendEmailVerifyTokenController))
usersRoute.post('/forgot-password', forgotPasswordValidator, wrapRequestHandler(ForgotPasswordController))
usersRoute.post(
  '/verify-forgot-password',
  verifyForgotPassWordTokenValidator,
  wrapRequestHandler(VerifyForgotPasswordTokenController)
)
usersRoute.post('/reset-password', resetPasswordValidator, wrapRequestHandler(ResetPasswordController))
usersRoute.get('/me', accessTokenValidator, wrapRequestHandler(getMeController))

export default usersRoute
