const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

const UserSchema = mongoose.Schema({
  username: {
    type: String,
    index: true
  },
  password: {
    type: String
  },
  email: {
    type: String
  },
  name: {
    type: String
  }
})

const User = module.exports = mongoose.model('User', UserSchema)

module.exports.createUser = (newUser, callback) => {
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      throw err
    }
    bcrypt.hash(newUser.password, salt, (err, salt) => {
      if (err) {
        throw err
      }

      newUser.password = salt
      newUser.save(callback)
    })
  })
}

module.exports.getUserByUsername = (username, callback) => {
  let query = {username: username}
  User.findOne(query, callback)
}

module.exports.getUserById = (id, callback) => {
  User.findById(id, callback)
}

module.exports.comparePassword = (candidatePassword, hash, callback) => {
  bcrypt.compare(candidatePassword, hash, (err, isMatch) => {
    if (err) {
      throw err
    }

    callback(null, isMatch)
  })
}
