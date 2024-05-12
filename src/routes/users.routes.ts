import { Router } from 'express'
import { LoginController, RegisterController } from '~/controllers/users.controllers'
import { loginValidator, registerValidator } from '~/middlewares/users.middlewares'
import { wrapRequestHandler } from '~/utils/handlers'

const usersRoute = Router()

usersRoute.post('/login', loginValidator, wrapRequestHandler(LoginController))
usersRoute.post('/register', registerValidator, wrapRequestHandler(RegisterController))

export default usersRoute
