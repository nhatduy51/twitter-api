import express from 'express'

import { defaultErrorHandler } from './middlewares/error.middlewares'
import usersRoute from './routes/users.routes'
import databaseService from './services/connect.db'

const app = express()
const port = 3000

databaseService.connect()

app.use(express.json())
//route user
app.use('/users', usersRoute)

app.use(defaultErrorHandler)

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
