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

const generateToken = async ( user ) => {
    const tokenData = {
        id: user._id.toString()
    }
    const accessToken = jwt.sign(tokenData, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: process.env.ACCESS_TOKEN_TIME
    });
    const refreshToken = jwt.sign(tokenData, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: process.env.REFRESH_TOKEN_TIME
    });
    return {accessToken, refreshToken};
}

const updateRefreshToken = async (id, refreshToken) => {
    return await UserModel.findByIdAndUpdate(id, { refreshToken });
}

const compare = (passw, hashpw) => {
    const hashpw2 = cryptojs.SHA256(passw).toString();
    return hashpw2 == hashpw;
}

app.get('/', (req, res) => {
    res.send('ok');
})

app.post('/register', async (req, res) => {
    console.log('Is register');
    const data = req.body;
    if (!data.email || !data.password) {
        return res.status(400).json({ message: 'Invalid request data' });
    }
    const passw = req.body.password;
    const hashpw = cryptojs.SHA256(passw).toString();
    const userData = {
        email: req.body.email,
        hashpw
    }
    try {
        const user = await UserModel.create(userData);
        const  { accessToken, refreshToken } = await generateToken(user);
        await updateRefreshToken(user._id.toString(), refreshToken);
        const uid = user._id.toString();
        return res.status(201).json({uid, accessToken});
    } catch (error) {
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: 'Invalid request data', error: error.message });
        } else if (error.code === 11000) {
            console.log('1100');
            return res.status(409).json({ message: 'Conflict: Duplicate data' });
        } else {
            return res.status(500).json({ message: 'Internal server error', error: error.message });
        }
    }
})


app.post('/login', async (req, res) => {
    console.log('Is login');
    const data = req.body;
    if (!data.email || !data.password) return res.status(400).json({ message: 'Invalid request data' });
    try {
        const user = await UserModel.findOne({ email: data.email });
        if (!user) return res.status(401).json({ message: 'Unauthorized' });
        if(!compare(data.password, user.hashpw)) return res.status(401).json({ message: 'Unauthorized' });
        const  { accessToken, refreshToken } = await generateToken(user);
        await updateRefreshToken(user._id.toString(), refreshToken);
        const uid = user._id.toString();
        return res.status(200).json({ uid, accessToken });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
})

app.post('/token', async (req, res) => {
    console.log('Is token');
    const rft = req.body.refreshToken;
    if (!rft) return res.status(401).json({ message: 'Unauthorized: No refresh token provided' });
    try {
        const rftData = jwt.verify(rft, process.env.REFRESH_TOKEN_SECRET);
        const user = await UserModel.findById(rftData.id);
        if(!user) return res.status(404).json({ message: 'User not found' });
        const { accessToken, refreshToken } = await generateToken(user);
        await updateRefreshToken(user._id.toString(), refreshToken);
        return res.status(200).json({ accessToken });
    } catch (error) {
        if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') return res.status(403).json({ message: 'Forbidden: Invalid or expired refresh token' });
        return res.status(500).json({ message: 'Internal server error' });
    }
})

app.get('/data', verifyToken, async (req, res) => {
    console.log('Is data');
    try {
        const user = await UserModel.findById(req.userId);
        if (!user) return res.status(404).json({ message: 'Resource not found' });
        return res.status(200).json(user);
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
})

app.delete('/logout', verifyToken, async (req, res) => {
    console.log('Is logout');
    try {
        await UserModel.findByIdAndUpdate(req.userId, { refreshToken: null });
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
})

app.listen(port, () => {
    console.log(`App listen on port:${port}`);
})