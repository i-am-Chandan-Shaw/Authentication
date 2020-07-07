//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const findOrCreate = require("mongoose-findorcreate")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const LinkedInStrategy = require('passport-linkedin').Strategy;
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'ejs');
app.use(express.static("public"));

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/secrets", {useUnifiedTopology: true, useNewUrlParser: true});


const userSchema=new mongoose.Schema({
  username: String,
  password: String,
  googleId:String,
  facebookId:String,
  linkedIn:String,
  secret: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// const secret ="This is not a secret"
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password'] });

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
      done(err, user);
    });

});
//////////////////////////////////////////////////////Facebook//////////////////////////////////////
passport.use(new FacebookStrategy({
    clientID: process.env.ID,
    clientSecret: process.env.SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
/////////////////////////////////Linked IN///////////////////

passport.use(new LinkedInStrategy({
    consumerKey: process.env.KEY,
    consumerSecret: process.env.SECRET_KEY,
    callbackURL: "http://127.0.0.1:3000/auth/linkedin/secrets"
  },
  function(token, tokenSecret, profile, done) {
    User.findOrCreate({ linkedinId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

/////////////////////////////////////////////Google///////////////////////////////////
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));
  ////////////////////////////LinkedIn///////////////////

  app.get('/auth/linkedin',
  passport.authenticate('linkedin'));

app.get('/auth/linkedin/secrets',
  passport.authenticate('linkedin', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

///////////////////////////Facebook///////////////////////
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });

//////////////////////////////////////REGISTER//////////////////////////////

app.get("/register", function(req, res){
  res.render("register");
})

app.post("/register", function(req,res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register")
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });



  // bcrypt.hash(req.body.password, saltRounds, function(err, hash){
  //   const newUser = new User({
  //     username: req.body.username,
  //     password: hash
  //   });
  //   newUser.save();
  //   res.redirect("login")
  // })

});

///////////////////////////////////////LOGIN////////////////////////////////

app.get("/login", function(req, res){
  res.render("login");
})

app.post("/login", function(req,res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  })

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets")
      })
    }
  })


  // const password = md5(req.body.password);
  // const password = req.body.password;
  // User.findOne({username: req.body.username},function(err, foundUser){
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if(foundUser){
  //     bcrypt.compare(password, foundUser.password, function(err, result){
  //       if(result==true){
  //         res.render("secrets");
  //       }
  //     })
  //   }
  // }
  // })
});

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}, function(err, foundUser){
      if (err) {
        console.log(err);
      } else {
        if (foundUser){
          res.render("secrets", {usersWithSecret: foundUser});
        }
      }
    });
  });
/////////////////Submit////////////////////////////////////
app.get("/submit", function(req, res){
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("login");
    }
  });

  app.post("/submit", function(req,res){
    const newSecret = req.body.secret;
    User.findById(req.user.id, function(err, foundUser){
      if (err) {
        console.log(err);
      } else {
        if(foundUser){
          foundUser.secret= newSecret;
          foundUser.save(function(){
            res.redirect("/secrets");
          });
        }
      }
    });
  });

  app.get("/logout", function(req,res){
    req.logout();
    res.redirect("/");
  });




app.listen(3000, function(){
  console.log("Server started at port 3000");
})
