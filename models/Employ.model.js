const mongoose = require('mongoose');

const EmploySchema = mongoose.Schema({
    email: { type: String, require: true },
    identify: { type: String , default: null },
    company: { type: String , default: null },
    cadd: { type: String , default: null },
    isVerified: { type: Boolean, default: false }
}, {
    timestamps: true
});

module.exports = mongoose.model('Employ', EmploySchema);