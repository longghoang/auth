const UserModel = require('../models/User.model');

module.exports = async function updateRefreshToken (id, refreshToken) {
    return await UserModel.findByIdAndUpdate(id, { refreshToken });
}