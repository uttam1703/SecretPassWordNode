//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose=require("mongoose");
const session = require('express-session');
const passport=require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


// const bcrypt = require('bcrypt');
// const saltRounds = 10;
//const md5 = require('md5');
// const encrypt = require('mongoose-encryption');

const PORT=process.env.PORT || 3000;



const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret: 'thisisVerySecretThing',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userScema= new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});

userScema.plugin(passportLocalMongoose);
userScema.plugin(findOrCreate);

// const secret=process.env.SECRET;
// userScema.plugin(encrypt,{secret:secret,encryptedFields:["password"]});

const User=mongoose.model("User",userScema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});



app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }

});

app.post("/submit",function(req,res){
    const sumbitSecret=req.body.secret;
    User.findById(req.body.id,function(err,result){
        if(err){
            console.log(err);
        }else{
            if(result){
                result.secret=sumbitSecret;
                result.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    })
});

app.get("/secrets",function(req,res){
    if(req.isAuthenticated()){
        res.render("secrets");
    }else{
        res.redirect("/login");
    }
})

app.post("/register",function(req,res){
    const email=req.body.username;
    const password=req.body.password;
    User.register({username:email},password,function(err,user){
        if(err){
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });

    
    
});

app.post("/login",function(req,res){
    const email=req.body.username;
    const password=req.body.password;
   
    const user=new User({
        username:email,
        password:password
    });
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });

});


app.listen(PORT,function(){
    console.log("start in 3000 port server");
})
