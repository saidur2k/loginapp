const express = require('express')
const path = require('path')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const exphbs = require('express-handlebars')
const expressValidator = require('express-validator')
const flash = require('connect-flash')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const mongo = require('mongodb')
const mongoose = require('mongoose')
const env = require('env2')('./env.json')
mongoose.connect(process.env.DB_LINK)
const db = mongoose.connection

const routes = require('./routes/index')
const users = require('./routes/users')

// Init App
const app = express()

// View Engine
app.set('views', path.join(__dirname, 'views'))
app.engine('handlebars', exphbs({defaultLayout: 'layout'}))
app.set('view engine', 'handlebars')

// BodyParser Middleware
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

// Set static folder
app.use(express.static(path.join(__dirname, 'public')))

// Express session
app.use(session({
  secret: process.env.EXPRESS_SECRET,
  saveUninitialized: true,
  resave: true
}))

// Passport Init
app.use(passport.initialize())
app.use(passport.session())

// Express Validator
app.use(expressValidator({
  errorFormatter: (param, msg, value) => {
    let namespace = param.split('.')
    let root = namespace.shift()
    let formParam = root

    while (namespace.length) {
      formParam += '[' + namespace.shift() + ']'
    }

    return {
      param: formParam,
      msg: msg,
      value: value
    }
  }
}))

// Connect flash
app.use(flash())

// Global Vars
app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg')
  res.locals.error_msg = req.flash('error_msg')
  res.locals.error = req.flash('error')
  res.locals.user = req.user || null
  next()
})

app.use('/', routes)
app.use('/users', users)

// Set port
app.set('port', (process.env.PORT || 3000))

app.listen(app.get('port'), () => {
  console.log('Server started on port ' + app.get('port'))
})
