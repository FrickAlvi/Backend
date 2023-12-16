var express = require('express');
var router = express.Router();

const {
  Login,
  Logout,
  refreshToken,
  register
} = require('../controllers/Auth');

router.post('/login', Login);
router.delete('/logout', Logout);
router.get('/token', refreshToken);
router.post('/register', register);

module.exports = router;
