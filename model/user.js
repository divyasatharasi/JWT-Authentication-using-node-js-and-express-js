var mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const config = require('../config/config').get(process.env.NODE_ENV);
const salt = 10;

const userSchema = mongoose.Schema({
    firstname: {
        type: String,
        required: true,
        maxlength: 10
    },
    lastname:{
        type: String,
        required: true,
        maxlength: 10
    },
    email:{
        type: String,
        required: true,
        unique: 1,
        trim: true 
    },
    password:{
        type: String,
        required: true,
        minlength: 8
    },
    password2:{
        type: String,
        required: true,
        minlength: 8
    },
    token:{
        type: String 
    }
});

userSchema.pre('save', function(next) {
    var user = this;
    if(user.isModified('password')) {
        bcrypt.genSalt(salt, function(err, salt){
            if(err) return next(err);
            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(err);
                user.password = hash;
                user.password2 = hash;
                next();
            });
        });
    } else {
        next();
    }
});

//comparing the password entered by user with our saved password
userSchema.methods.comparePassword = function(password, cb) {
    bcrypt.compare(password, this.password, (err, isMatch) => {
        if(err) cb(next);
        cb(null, isMatch);
    })
}

//function for generating a token when user logged in.
userSchema.methods.generateToken = function(cb) {
    let user = this;
    let token = jwt.sign(user._id.toHexString(), config.SECRET);

    user.token = token;
    user.save(function(err, user){
        if(err) return cb(err);
        cb(null, user);
    })
};

//find by token - used to find whether a user is logged-in or not
userSchema.statics.findByToken = function(token, cb) {
    let user= this;
    jwt.verify(token, config.SECRET, function(err, decode){
        if(err) return cb(err);
        user.findOne({"_id": decode, "token": token}, function(err, user){
            if(err) return cb(err);
            cb(null, user);
        })
    })
};

//delete a token - delete particular token when the user logout
userSchema.methods.deleteToken = function(token, cb) {
    let user = this;
    user.update({$unset : {token: 1}}, function(err, user) {
        if(err) return cb(err);
        cb(null, user);
    })
}
module.exports = mongoose.model('User', userSchema);