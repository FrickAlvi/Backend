require('dotenv').config();
var cors = require('cors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var authRouter = require('./routes/auth');
var indexRouter = require('./routes/index');
var userRouter = require('./routes/user');
var predictRouter = require('./routes/predict');
var transaksiRouter = require('./routes/transaksi');

const app = express();

var whitelisted = process.env.WHITELISTED.split(';');

let whitelist = whitelisted;

app.use(express.json());

app.use(cors({
  credentials: true,
  origin: function (origin, callback) {
    // allow requests with no origin 
    if (!origin) return callback(null, true);
    if (whitelist.indexOf(origin) === -1) {
      var message = 'The CORS policy for this origin doesn\'t ' +
        'allow access from the particular origin.';
      return callback(new Error(message), false);
    }
    return callback(null, true);
  },
  exposedHeaders: ['set-cookie']
}));
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/auth', authRouter);
app.use('/', indexRouter);
app.use('/user', userRouter);
app.use('/predict', predictRouter);
app.use('/transaksi', transaksiRouter);

module.exports = app;
