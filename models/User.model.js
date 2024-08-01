const mongoose = require('mongoose');

const UserSchema = mongoose.Schema({
    email: { type: String, require: true },
    hashpw: { type: String, default: null},
    name: { type: String , default: 'User' },
    avt: { type: Buffer , default: null },
    add: { type: String , default: null },
    birth: { type: String, default: null},
    phoneNum: { type: String , default: null },
    level: { type: Number, default: 0 },
    isVerified: { type: Boolean, default: false },
    verificationCode: { type: String, default: null },
    verificationCodeExpires: { type: Date, default: null },
    method: { type: String, default: 'email' },
    refreshToken: { type: String, default: null }
}, {
    timestamps: true
});

module.exports = mongoose.model('User', UserSchema);