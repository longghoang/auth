const jwt = require('jsonwebtoken');

exports.verifyToken = (req, res, next) => {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access token is missing' });
    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.userId = decoded.id;
        next();
    } catch (error) {
        console.log('Is verify');
        if (error.name === 'TokenExpiredError') {
            return res.status(403).json({ message: 'Access token has expired' });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({ message: 'Invalid access token' });
        } else {
            return res.status(403).json({ message: 'Forbidden' });
        }
    }
}