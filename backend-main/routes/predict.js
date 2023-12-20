var express = require('express');
const Multer = require('multer');
var router = express.Router();

const {
  predictMainBali,
  predictMainSunda,
  predictMainLampung,
  predictRandom
} = require('../controllers/Predict');

const multer = Multer({
  storage: Multer.memoryStorage()
});

router.post('/lampung', multer.single('file'), predictMainLampung);
router.post('/sunda', multer.single('file'), predictMainSunda);
router.post('/bali', multer.single('file'), predictMainBali);
router.post('/random', predictRandom);

module.exports = router;
