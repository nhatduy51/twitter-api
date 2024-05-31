import { Router } from 'express'
import { LoginController, LogoutController, RegisterController } from '~/controllers/users.controllers'
import { accessTokenValidator, loginValidator, registerValidator } from '~/middlewares/users.middlewares'
import { wrapRequestHandler } from '~/utils/handlers'

const usersRoute = Router()

usersRoute.post('/login', loginValidator, wrapRequestHandler(LoginController))
usersRoute.post('/register', registerValidator, wrapRequestHandler(RegisterController))
usersRoute.post(
  '/logout',
  accessTokenValidator,
  wrapRequestHandler((req, res) => {
    res.json({ msg: 'logout successfully' })
  })
)

export default usersRoute
