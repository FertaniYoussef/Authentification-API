const router = require('express').Router()
const User = require('../data/User')
const verify = require('./verifyToken')

router.get('/', verify, (req, res) => {
    res.send(req.user)
})


module.exports = router;