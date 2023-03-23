const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const db = require('./database');
require('dotenv').config();

const app = express();
const PORT = 8000;
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

const defaultUsers = [
    ['id1', 'user1', 'student1', 'password'],
    ['id2', 'user2', 'student2', 'password2'],
    ['id3', 'user3', 'teacher', 'password3'],
    ['admin', 'admin', 'admin', 'admin'],
];

defaultUsers.forEach((user) => createUsers(...user));

app.get('/', (req, res) => {
    res.redirect('/identify');
});

app.get('/identify', (req, res) => {
    res.render('identify.ejs');
});
app.get('/granted', authenticateToken, (req, res) => {
    res.render('start.ejs');
});

app.get(
    '/student1',
    authenticateToken,
    authorizeRole(['student1', 'teacher', 'admin']),
    (req, res) => {
        res.render('student1.ejs');
    }
);

app.get(
    '/student2',
    authenticateToken,
    authorizeRole(['student2', 'teacher', 'admin']),
    async (req, res) => {
        const user = await getUserFromToken(req)
        res.render('student2.ejs', { user: user });
    }
);

app.get(
    '/teacher',
    authenticateToken,
    authorizeRole(['teacher', 'admin']),
    (req, res) => {
        res.render('teacher.ejs');
    }
);

app.get(
    '/admin',
    authenticateToken,
    authorizeRole(['admin']),
    async (req, res) => {
        const users = await db.getUsers();
        res.render('admin.ejs', { users });
    }
);
app.post('/identify', async (req, res) => {
    try {
        const { userId, password } = req.body;

        if (userId && password) {
            const dbUser = await db.getUser(userId);
            const userPassword = await db.getPasswordForUser(userId);
            const passwordMatch = await bcrypt.compare(password, userPassword);

            if (passwordMatch) {
                const userObj = { username: userId, role: dbUser.role };
                const token = jwt.sign(userObj, ACCESS_TOKEN_SECRET);
                res
                    .cookie('jwt', token, { httpOnly: true })
                    .status(200)
                    .redirect('/granted');
                return;
            }
        }

        res.redirect('/identify');
    } catch (error) {
        console.error(error);
        res.redirect('/identify');
    }
});

app.get('/granted', authenticateToken, (req, res) => {
    res.render('start.ejs');
});

app.get(
    '/admin',
    authenticateToken,
    authorizeRole(['admin']),
    async (req, res) => {
        const users = await db.getUsers();
        res.render('admin.ejs', { users });
    }
);

function authenticateToken(req, res, next) {
    const token = req.cookies.jwt;

    if (!token || !jwt.verify(token, ACCESS_TOKEN_SECRET)) {
        return res.redirect('/identify');
    }

    next();
}

async function createUsers(username, name, role, password) {
    const encryptedPassword = await bcrypt.hash(password, 10);
    await db.addUser(username, name, role, encryptedPassword);
}

function authorizeRole(requiredRoles) {
    return async (req, res, next) => {
        try {
            const user = await getUserFromToken(req);

            if (!requiredRoles.includes(user.role)) {
                return res.redirect('/identify');
            }

            next();
        } catch (error) {
            console.error(error);
            res.redirect('/identify');
        }
    };
}

async function getUserFromToken(req) {
    const token = req.cookies.jwt;
    const { username } = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const user = await db.getUser(username);
    return user;
}

app.listen(PORT, () => {
    console.log(`Server is up on port ${PORT}`);
});