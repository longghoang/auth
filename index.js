const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cryptojs = require('crypto-js');

dotenv.config();

const db = require('./configs/db/index.db');

const UserModel = require('./models/User.model');
const EmployModel = require('./models/Employ.model');

const { verifyToken } = require('./middlewares/auth');

const generateToken = require ('./utils/generateToken.util');
const updateRefreshToken = require ('./utils/updateRefreshToken.util');
const compare = require ('./utils/compare.util');
const verifyEmailCode = require ('./utils/verifyEmailCode.util');

const app = express();
const port = process.env.AUTH_SERVER_PORT || 3333;

db.connect();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.send('ok');
})

app.post('/register', async (req, res) => {
    console.log('Is register');
    const data = req.body;
    if (!data.email || !data.password) {
        return res.status(400).json({ message: 'Invalid request data' });
    }
    const verificationCode = await verifyEmailCode(data.email);
    const verificationCodeExpires = new Date(Date.now() + 3600000);
    const passw = data.password;
    const hashpw = cryptojs.SHA256(passw).toString();
    const userData = {
        email: data.email,
        hashpw,
        verificationCode,
        verificationCodeExpires
    }
    try {
        const user = await UserModel.create(userData);
        return res.status(201)
        .json({uid: user._id.toString()});
    } catch (error) {
        console.log(error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: 'Invalid request data', error: error.message });
        } else if (error.code === 11000) {
            console.log('1100');
            return res.status(409).json({ message: 'Conflict: Duplicate data' });
        } else {
            return res.status(500).json({ message: 'Internal server error', error: error.message });
        }
    }
});

app.post('/verify', async (req, res) => {
    const data = req.body;
    if(!data.uid || !data.code) return res.status(400).json({ message: 'Invalid request data' });
    try {
        const user = await UserModel.findById(data.uid);
        if (!user) return res.status(401).json({ message: 'Unauthorized' });
        if(data.code !== user.verificationCode) return res.status(401).json({ message: 'Unauthorized' });
        await UserModel.findByIdAndUpdate(data.uid, { isVerified: true });
        const  { accessToken, refreshToken } = await generateToken(user);
        await updateRefreshToken(user._id.toString(), refreshToken);
        const uid = user._id.toString();
        return res.status(200).json({ uid, accessToken });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
})

app.post('/register-firebase', async (req, res) => {
    console.log('Is register firebase');
    const data = req.body;
    if (!data.email || !data.password || !data.name) {
        return res.status(400).json({ message: 'Invalid request data' });
    }
    const passw = data.password;
    const hashpw = cryptojs.SHA256(passw).toString();
    const userData = {
        email: data.email,
        hashpw,
        name: data.name,
        method: data.method
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


app.post('/login-firebase', async (req, res) => {
    console.log('Is login firebase');
    const data = req.body;
    if (!data.email) return res.status(400).json({ message: 'Invalid request data' });
    try {
        const user = await UserModel.findOne({ email: data.email });
        if (!user) return res.status(401).json({ message: 'Unauthorized' });
        const  { accessToken, refreshToken } = await generateToken(user);
        await updateRefreshToken(user._id.toString(), refreshToken);
        const uid = user._id.toString();
        return res.status(200).json({ uid, accessToken });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
})

app.patch('/update-info', async (req, res) => {
    console.log('Is login firebase');
    const data = req.body;
    if (!data.email || !data.uid) return res.status(400).json({ message: 'Invalid request data' });
    try {
        await UserModel.findByIdAndUpdate(data.uid, { email: data.email, birth: data.birth, add: data.add, sdt: data.sdt });
        return res.sendStatus(200);
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

app.post('/register-employ', async (req, res) => {
    console.log('Is register employ');
    const data = req.body;
    if (!data.email || !data.cadd || !data.identify || !data.company) {
        return res.status(400).json({ message: 'Invalid request data' });
    }
    try {
        const user = await EmployModel.create(data);
        const uid = user._id.toString();
        await UserModel.findOneAndUpdate({ email: user.email }, { level: 99 });
        return res.sendStatus(200);
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