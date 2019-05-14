const mongoose = require('mongoose')
const validator = require('validator')
const bcryptjs = require('bcrypt')
const jwt = require('jsonwebtoken')

const Schema = mongoose.Schema

const userSchema = new Schema({
    username:{
        type : String,
        required : true,
        unique : true
    },
    email:{
        type : String,
        required : true,
        unique : true,
        validate: {
            validator: function (value) {
                return validator.isEmail(value)
            },
            message: function () {
                return 'Invalid email format'
            }
        }

    },
    password:{
        type: String,
        required: true,
        minlength: 6,
        maxlength: 128
    },
    roles: {
        type: [String],
        default: 'customer'
    },
    tokens: [
        {
            token: {
                type: String
            },
            createdAt: {
                type: Date,
                default: Date.now
            }
        }
    ]
   })

userSchema.statics.findByToken = function (token) {
    const User = this
    let tokenData
    try {
        tokenData = jwt.verify(token, 'jwt@123')
    } catch (err) {
        return Promise.reject(err)
    }

    return User.findOne({
        _id: tokenData._id,
        'tokens.token': token
})
}

userSchema.statics.findByCredentials = function (email, password) {
    const User = this
    return User.findOne({ email })
        .then(function (user) {
            if (!user) {
                return Promise.reject({error:'invalid email / password'})
            }
            return bcryptjs.compare(password, user.password)
                .then(function (result) {
                    if (result) {
                        return Promise.resolve(user)
                    } else {
                        return Promise.reject({error:'invalid email / password'})
                    }
                })
        })
        .catch(function (err) {
            return Promise.reject(err)
        })
}

userSchema.methods.generateToken = function () {
    const user = this
    const tokenData = {
        _id: user._id,
        username: user.username,
        createdAt: Number(new Date())
    }

    const token = jwt.sign(tokenData, 'jwt@123')
    user.tokens.push({
        token
    })

    return user.save()
        .then(function (user) {
            return Promise.resolve(token)
        })
        .catch(function (err) {
            return Promise.reject(err)
        })
}

userSchema.pre('save',function(next){
const user = this
if(user.isNew){
    function encryptPassword() {
        return bcryptjs.genSalt(10)
            .then(function (salt) {
                return bcryptjs.hash(user.password, salt)
                    .then(function (encryptedPassword) {
                        user.password = encryptedPassword
                    })
            })
        }

        function setRole() {
            return User.countDocuments()
                .then(function(count){
                    if(count==0){
                        user.roles = ['admin','customer']
                    }
                })
            }
            
        return Promise.all([encryptPassword(), setRole()])
            .then(function(values){
                    next()
            })
            .catch(function(err){
                return Promise.reject(err.message)
            })
}
else {
    next()
}
})

const User = mongoose.model('User', userSchema)

module.exports = {
        User
    }