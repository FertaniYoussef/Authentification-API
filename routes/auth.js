const router = require('express').Router()
const User = require('../data/User')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const { registerValidation, loginValidation } = require('../validation')




router.post('/register', async (req, res) => {

    // DATA VALIDATION
    const { error } = registerValidation(req.body)
    if (error) res.status(400).send(error.details[0].message)
    else {
        //Check if email already exist
        const emailExist = await User.findOne({ email: req.body.email })
        if (emailExist) return res.status(400).send('Email Already Exist')
        else {

            //Hash passwords
            const salt = await bcrypt.genSalt(10)
            const hashPassword = await bcrypt.hash(req.body.password, salt)
            console.log(hashPassword)

            //Create the new user
            const user = new User({
                name: req.body.name,
                email: req.body.email,
                password: hashPassword
            })
            //Save it into ther database
            try {
                const savedUser = await user.save()
                res.send({ user: user._id })
            } catch (err) {
                res.status(400).send(err)
            }
        }
    }
})

router.post('/login', async (req, res) => {
    // DATA VALIDATION
    const { error } = loginValidation(req.body)
    if (error) res.status(400).send(error.details[0].message)
    else {
        //Check if email is present and password valid
        const user = await User.findOne({ email: req.body.email })

        if (!user) return res.status(400).send('Email or password doesn\'t exist')
        else {
            const validPass = await bcrypt.compare(req.body.password, user.password)
            if (!validPass) return res.status(400).send('Email or password doesn\'t exist')



            else {
                //Create and assign a token 
                const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET)
                res.header('auth-token', token).send(token)
            }
        }
    }
})

module.exports = router;