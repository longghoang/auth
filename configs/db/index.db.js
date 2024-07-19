const mongoose = require('mongoose');

const connect = () => {
    mongoose.connect(process.env.MONGODB_URI)
    .then(response => {
        console.log('Connect mongodb success!');
    })
    .catch(error => {
        console.log('Connect fail!');
        console.log('Error', error);
    })
}

module.exports = { connect };
