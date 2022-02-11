const express = require('express')
const app = express();
const mongoose = require('mongoose')
const dotenv = require('dotenv')

dotenv.config()


//Import Routes
const authRoute = require('./routes/auth')
const postRoute= require('./routes/posts')

//Connection to DB
mongoose.connect(process.env.DB_CONNECT,
    { useNewUrlParser: true },
    (err) => console.log('connected to db!')
);

//Middleware
app.use(express.json())

//Route Middleware
app.use('/api/user', authRoute)
app.use('/api/posts',postRoute)


app.listen(3000, () => console.log('up and running'))

