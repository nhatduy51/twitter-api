import { config } from 'dotenv'
import jwt from 'jsonwebtoken'
config()
export const signToken = ({
  payload,
  privateKey = process.env.JWT_SECRET as string,
  option = {
    algorithm: 'HS256'
  }
}: {
  payload: string | Buffer | object
  privateKey?: string
  option?: jwt.SignOptions
}) => {
  return new Promise((resolve, reject) => {
    jwt.sign(payload, privateKey, option, (error, token) => {
      if (error) {
        throw reject(error)
      }
      resolve(token as string)
    })
  })
}
