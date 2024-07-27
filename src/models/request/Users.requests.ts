import { JwtPayload } from "jsonwebtoken"
import { tokenType } from "~/constants/enum"


export interface LoginRequestBody {
  email: string
  password: string
}
export interface RegisterRequestBody {
  name: string
  email: string
  password: string
  confirm_password: string
  day_of_birth: string
}

export interface LogoutRequestBody {
  refresh_token: string
}

export interface TokenPayload extends JwtPayload {
  user_id: string
  token_type: tokenType
}

export interface ForgotPasswordRequestBody {
  email: string
}

export interface VerifyForgotPasswordTokenPayload {
  forgot_password_token: string
}

export interface UpdateMeRequestBody {
  name?: string
  date_of_birth?: string
  bio?: string
  location?: string
  website?: string
  username?: string
  avatar?: string
  cover_photo?: string
}

export interface FollowReqBody {
  followed_user_id: string
}

export interface UnFollowReqBody {
  user_id: string
}
