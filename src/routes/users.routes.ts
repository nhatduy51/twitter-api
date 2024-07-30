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
  getMeController,
  updateMeController,
  getProfileController,
  followController,
  unFollowController,
  OAuthController
} from '~/controllers/users.controllers'
import { filterMiddleware } from '~/middlewares/common.middleware'
import {
  accessTokenValidator,
  emailVerifyTokenValidator,
  forgotPasswordValidator,
  loginValidator,
  refreshTokenValidator,
  registerValidator,
  verifyForgotPassWordTokenValidator,
  resetPasswordValidator,
  verifiedUserValidator,
  updateMeValidator,
  followValidator,
  unFollowValidator
} from '~/middlewares/users.middlewares'
import { UpdateMeRequestBody } from '~/models/request/Users.requests'
import { wrapRequestHandler } from '~/utils/handlers'

const usersRoute = Router()

usersRoute.post('/login', loginValidator, wrapRequestHandler(LoginController))
usersRoute.get('/oauth/google', wrapRequestHandler(OAuthController))
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

usersRoute.patch(
  '/me',
  accessTokenValidator,
  verifiedUserValidator,
  updateMeValidator,
  filterMiddleware<UpdateMeRequestBody>([
    'name',
    'date_of_birth',
    'bio',
    'location',
    'website',
    'avatar',
    'username',
    'cover_photo'
  ]),
  wrapRequestHandler(updateMeController)
)
usersRoute.get('/:username', wrapRequestHandler(getProfileController))

usersRoute.post(
  '/follow',
  accessTokenValidator,
  verifiedUserValidator,
  followValidator,
  wrapRequestHandler(followController)
)

usersRoute.delete(
  '/follow/:user_id',
  accessTokenValidator,
  verifiedUserValidator,
  unFollowValidator,
  wrapRequestHandler(unFollowController)
)

export default usersRoute
