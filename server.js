const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
require('dotenv').config()
const db = require('./database')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser');

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(express.json())

var currentKey = ""
var currentPassword = ""

app.get('/', (req, res) => {
    res.redirect("/identify")
})

app.post('/identify', async (req, res) => {

    if (req.body.userId && req.body.password) {
        // Gets the encrypted password from the db
        var correctPassword = await db.getPasswordForUser(req.body.userId)
        // Compares the encrypted passwords
        var passwordMatches = await bcrypt.compare(req.body.password, correctPassword)
        if (passwordMatches) {
            const username = req.body.password
            const token = jwt.sign(username, process.env.ACCESS_TOKEN_SECRET)
            currentKey = token
            currentPassword = username
            res.redirect("/granted")
        }
        else {
            res.redirect("/identify")
        }
    } else {
        res.redirect("/identify")
    }


})

app.get('/identify', (req, res) => {
    res.render("identify.ejs")
})

app.get('/admin', authenticateToken, authorizeRole(["admin"]), async (req, res) => {
    users = await db.getUsers();
    res.render("admin.ejs", users)
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

function authorizeRole(requiredRoles) {
    return async (req, res, next) => {
        try {
            const user = await getUserFromToken(req);

            if (requiredRoles.includes(user.role)) {
                next();
            } else {
                res.sendStatus(401);
            }
        } catch (error) {
            console.log(error)
        }
    }
}
async function getUserFromToken(req) {
    const token = req.cookies.jwt;
    const decryptedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await db.getUser(decryptedToken.username);
    return user;
}

app.get('/granted', authenticateToken, (req, res) => {
    res.render("start.ejs")
})

async function addUser(username, name, role, password) {
    let encryptedPassword = await bcrypt.hash(password, 10);
    await db.addUser(username, name, role, encryptedPassword)
}
addUser('id1', 'user1', 'student1', 'password')
addUser('id2', 'user2', 'student2', 'password2')
addUser('id3', 'user3', 'teacher', 'password3')
addUser('admin', 'admin', 'admin', 'admin')

app.listen(8000, () => {
    console.log("Server is running on port 8000")
})