const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cryptojs = require('crypto-js');

const db = require('./configs/db/index.db');

const UserModel = require('./models/Users.model');

const { verifyToken } = require('./middlewares/auth');

const app = express();
const port = process.env.AUTH_SERVER_PORT || 3333;

dotenv.config();
db.connect();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const generateToken = payload => {
    const tokenData = {
        id: payload._id
    }
    const accessToken = jwt.sign(tokenData, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '15m'
    });
    const refreshToken = jwt.sign(tokenData, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: '30d'
    });
    return {accessToken, refreshToken};
}

const updateRefreshToken = (id, refreshToken) => {
    UserModel.findByIdAndUpdate(id, { refreshToken });
}

const compare = (passw, hashpw) => {
    const hashpw2 = cryptojs.SHA256(passw).toString();
    return hashpw2 == hashpw;
}

app.get('/', (req, res) => {
    res.send('ok');
})

app.post('/register', (req, res) => {
    const passw = req.body.password;
    const hashpw = cryptojs.SHA256(passw).toString();
    const data = {
        email: req.body.email,
        hashpw
    }
    UserModel.create(data)
        .then(user => {
            const  { accessToken, refreshToken } = generateToken(user);
            updateRefreshToken(user._id.toString(), refreshToken);
            res.json({
                accessToken
            });
        })
        .catch(error => {
            console.log('Error: ', error)
            res.sendStatus(409);
        })
})

app.post('/login', (req, res) => {
    const data = req.body;
    UserModel.findOne({ email: data.email })
        .then(user => {
            if(!compare(data.password, user.hashpw)) return res.sendStatus(401);
            const { accessToken, refreshToken } = generateToken(user);
            updateRefreshToken(user._id.toString(), refreshToken);
            res.json({
                accessToken
            });
        })
        .catch(error =>{
            console.log("Error: ", error);
            res.sendStatus(401);
        });
})

app.post('/token', (req, res) => {
    const refreshToken = req.body.refreshToken;
    if (!refreshToken) return res.sendStatus(401);
    try {
        const refreshData = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        UserModel.findById(refreshData.id)
            .then(user => {
                const { accessToken, refreshToken } = generateToken(user);
                updateRefreshToken(user._id.toString(), refreshToken);
                res.json({
                    accessToken
                });
            })
            .catch(error =>{
                console.log("Error: ", error);
                res.sendStatus(401);
            });
    } catch (error) {
        console.log(error);
        res.sendStatus(403);
    }
})

app.get('/data', verifyToken, (req, res) => {
    UserModel.findById(req.userId)
        .then(response => {
            res.json(response);
        })
        .catch(error => {
            console.log(error);
            res.sendStatus(403);
        })
})

app.delete('/logout', verifyToken, (req, res) => {
    UserModel.findByIdAndUpdate(req.userId, { refreshToken: null });
    res.sendStatus(204);
})

app.listen(port, () => {
    console.log(`App listen on port:${port}`);
})