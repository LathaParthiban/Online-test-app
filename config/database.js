const mongoose = require('mongoose')

mongoose.Promise = global.Promise

mongoose.connect('mongodb://localhost:27017/online-test-app', { useNewUrlParser: true, useCreateIndex: true})
    .then(function () {
        console.log('connected to db')
    })
    .catch(function (err) {
        console.log('error connecting to db',err)
    })

module.exports = {
    mongoose
}