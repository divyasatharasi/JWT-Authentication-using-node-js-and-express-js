const express = require('express');
const bodyparser = require('body-parser');
const mongoose = require('mongoose');
const cookieparser = require('cookie-parser');

const User = require('./model/user');
const {auth} = require('./middleware/auth');

//connect our app to the database
const db = require('./config/config').get(process.env.NODE_ENV);

const app = express();

// app use
app.use(bodyparser.urlencoded({extended: false}));
app.use(bodyparser.json());
app.use(cookieparser());

//data connection
mongoose.Promise = global.Promise;
mongoose.connect(db.DATABASE, {useNewUrlParser: true, useUnifiedTopology: true}, function(err){
    if(err) {
        console.log(err);
    }
    console.log("Database is connected");
})

// app routes
app.get('/', function(req, res) {
    res.status(200).send('Welcome!!!');
});

//Adding new user ( sign-up route)
app.post('/api/register', function(req, res) {
    let newUser = User(req.body);

    if(newUser.password != newUser.password2) return res.status(400).json({message: 'password doesnot match'});

    User.findOne({email: newUser.email}, function(err, user) {
        if(user) return res.status(400).json({message: 'email exists'});

        newUser.save((err, doc) => {
            if(err) {
                console.log(err);
                return res.status(400).json({ success: false});
            }
            res.status(200).json({
                success: true, 
                user: doc
            });
        });
    });
});

//User login route
app.post('/api/login', (req, res) => {
    let token = req.cookies.auth;

    User.findByToken(token, (err, user) => {
        // if(err) return res.send(err);
        if(user) return res.status(400).json({
            error: true,
            message: "You are already logged in"
        });
        else {
            User.findOne({email: req.body.email}, function(err, user) {
                if(!user) return res.json({isAuth: false, message: 'Auth failed, email not found' });
                
                user.comparePassword(req.body.password, (err, isMatch) => {
                    if(!isMatch) return res.json({ isAuth: false, message: 'password doesnot match'});
                    user.generateToken((err, user) => {
                        if(err) return res.status(400).send(err);
                        res.cookie('auth', user.token).json({
                            isAuth: true, 
                            id: user._id,
                            email: user.email,
                            name: `${user.firstname} ${user.lastname}`
                        });
                    });
                });
            });
        }
    });
});

//get logged in user
app.get('/api/profile', auth, (req, res) => {
    res.json({
        isAuth: true, 
        id: req.user._id,
        email: req.user.email,
        name: `${req.user.firstname} ${req.user.lastname}`
    });
});

//logout user
app.get('/api/logout', auth, (req, res) => {
    req.user.deleteToken(req.token, (err, user) => {
        if(err) return res.status(400).send(err);
        res.sendStatus(200);
    });
});

//app listening
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('app is running at:', PORT);
});