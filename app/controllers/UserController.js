const express = require('express')
const _ = require('lodash')
const router = express.Router()
const {User} = require('../models/User')


router.post('/register',function(req,res){
    const body = _.pick(req.body,['username','email','password'])
    const user = new User(body)
    user.save()
        .then(function(user){
             res.send(user)
        })
        .catch(function(err){
             res.send(err)
        })
      
})

router.post('/login', function (req, res) {
    const body = req.body
    User.findByCredentials(body.email, body.password)
        .then(function (user) {
            return user.generateToken()
        })
        .then(function (token) {
            res.setHeader('x-auth', token).send({})
        })
        .catch(function (err) {
            res.send(err)
        })
})


module.exports = {
    usersRouter : router
}