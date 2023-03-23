const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
require('dotenv').config()

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(express.json())

var currentKey = ""
var currentPassword = ""

app.get('/', (req, res) => {
    res.redirect("/identify")
})

app.post('/identify', (req, res) => {
    const username = req.body.password
    const token = jwt.sign(username, process.env.ACCESS_TOKEN_SECRET)
    currentKey = token
    currentPassword = username
    res.redirect("/granted")
})

app.get('/identify', (req, res) => {
    res.render("identify.ejs")
})



function authenticateToken(req, res, next) {
    if (currentKey == "") {
        res.redirect("/identify")
    } else if (jwt.verify(currentKey, process.env.ACCESS_TOKEN_SECRET)) {
        next()
    } else {
        res.redirect("/identify")
    }
}

app.get('/granted', authenticateToken, (req, res) => {
    res.render("start.ejs")
})



app.listen(8000, () => {
    console.log("Server is running on port 8000")
})