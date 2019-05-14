const express = require('express')
const router = express.Router() 

const { usersRouter } = require('../app/controllers/UserController')

router.use('/users', usersRouter)

module.exports = {
    routes: router 
}