const path = require('path');
const nodemailer = require('nodemailer');
const ejs = require('ejs');
const fs =require('fs');

function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.APP_EMAIL,
        pass: process.env.APP_EMAIL_PASS
    }
});

async function renderTemplate(templatePath, data) {
    const template = fs.readFileSync(path.resolve(__dirname, templatePath), 'utf-8');
    return ejs.render(template, data);
}
async function sendVerificationEmail(toEmail, verificationCode) {
    try {
        const mailForm = await renderTemplate('../views/email.ejs', { verificationCode });
        const mailOptions = {
            from: `SMART PARKING APP <${process.env.ADMIN_EMAIL}>`,
            to: toEmail,
            subject: 'Your Verification Code',
            html: mailForm
        };
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error("Error sending email:", error);
    }
}

module.exports = async function verifyEmailCode (email) {
    const verifyCode = generateVerificationCode();
    await sendVerificationEmail(email, verifyCode);
    return verifyCode;
}