const jwt = require('jsonwebtoken');

module.exports = async function generateToken( user ){
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