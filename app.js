require('dotenv').config(); //run this at top
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
//const _ = require("lodash"); //For word processing
const mongoose = require("mongoose");

//Level 6 security - cookies
//PLM can remember if a user is authed, using cookies
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.set('view engine', 'ejs');
app.use(express.static('public/'));
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize()); //setup passport
app.use(passport.session()); //use passport to deal with sessions

// ============= DB Setup =================//
mongoose.connect("mongodb://localhost:27017/secretsDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String
});

userSchema.plugin(passportLocalMongoose); //extend mongodb with passport stuff
userSchema.plugin(findOrCreate); //extend mongodb with passport stuff

const User = mongoose.model("User", userSchema);

//======== Setup passport strategies ========//
passport.use(User.createStrategy()); // use static authenticate method of model in LocalStrategy
//Works for any serialization, including google
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done){
  User.findById, function(err, user) {
    done(err,user);
  };
});

//Setup OAUTH google 2.0
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //This is a passport pseudocode, you must setup find and create route
    //Angela points to a npm module that implements it
    console.log("User login from: " + profile.displayName);

    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));




// const welcome = new Post({
//   title: "Welcome!",
//   content: "This is a simple blog website that I made during my web development course. It uses templating with EJS and saves blog posts to a Mongo database."
// });




app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google",
  //initiate google authed
  passport.authenticate("google", {
    scope: ["profile"]
  }) //user's google profile, email, id etc
);

//Get the redirect once google login confirmed
app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  //use passportLocalMongoose to check user is authenticated
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res) {
  //use PLM to deauth user
  req.logout();
  res.redirect("/");
});



app.post("/register", function(req, res) {
  //use passport local mongoose to register()
  //PLM handles registrations
  User.register({
    username: req.body.username
  }, req.body.password, function(err, newUser) {
    if (err) {
      console.log(err);
      res.redirect("/");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      })
    }
  })
});


app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //Now use passport to login and auth this user
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      })
    }
  })

});




app.listen(3000, function() {
  console.log("app.js running on port 3000");
});
