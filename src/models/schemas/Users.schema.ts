import { ObjectId } from 'mongodb'
import { UserVerifyStatus } from '~/constants/enum'

interface UserType {
  _id?: ObjectId
  name?: string
  email: string
  date_of_birth?: Date
  password: string
  created_at?: Date
  updated_at?: Date
  email_verify_token: string
  forgot_password_token?: string
  verify?: UserVerifyStatus

  bio?: string
  location?: string
  website?: string
  username?: string
  avatar?: string
  cover_photo?: string
}

export default class User {
  _id?: ObjectId
  name: string
  email: string
  date_of_birth: Date
  password: string
  created_at: Date
  updated_at: Date
  email_verify_token: string
  forgot_password_token: string
  verify: UserVerifyStatus

  bio: string
  location: string
  website: string
  username: string
  avatar: string
  cover_photo: string

  constructor(User: UserType) {
    this._id = User._id
    this.name = User.name || ''
    this.email = User.email
    this.date_of_birth = User.date_of_birth || new Date()
    this.password = User.password
    this.created_at = User.created_at || new Date()
    this.updated_at = User.updated_at || new Date()
    this.email_verify_token = User.email_verify_token || ''
    this.forgot_password_token = User.forgot_password_token || ''
    this.verify = User.verify || UserVerifyStatus.Unverified
    this.bio = User.bio || ''
    this.location = User.location || ''
    this.website = User.website || ''
    this.username = User.username || ''
    this.avatar = User.avatar || ''
    this.cover_photo = User.cover_photo || ''
  }
}
