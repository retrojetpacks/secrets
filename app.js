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
const FacebookStrategy = require("passport-facebook").Strategy;
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
  //place user's id in a cookie
  done(null, user.id);
});

// passport.deserializeUser(function(id, done) {
//   User.findById,
//     function(err, user) {
//       done(err, user);
//     };
// });

passport.deserializeUser(function(id, done) {
  //retrieve user from database by id
  User.findById(id,
    function(err, user) {
      done(err, user);
    });
});



//Setup OAUTH google 2.0
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
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


//Test facebook oauth2
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id
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


//================= Third Party OAUTH ==================//
app.get("/auth/google",
  //initiate google authed
  passport.authenticate("google", {
    scope: ["profile", "email"]
  }) //user's google profile, email, id etc
);

//Get the redirect once google login confirmed
app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    console.log("redirected from google");
    // Successful authentication, redirect home.
    //console.log(req);
    //console.log(res);
    //BUG!! /does not redirect, even to root /
    //res.redirect("/secrets");
    //res.redirect("/");
    res.render("secrets");
    //res.send(req.user);
  });


  app.get("/auth/facebook",
    //initiate facebook authed
    passport.authenticate("facebook", {
      //scope: ["profile"]
    })
  );

  app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", {
      successRedirect: "/secrets",
      failureRedirect: "/login"
    }),
    // function(req, res) {
    //   console.log("redirected from facebook");
    //   res.render("secrets");
    // }
  );




app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  //BUG!!!! Doesn't reach secrets and log this
  //use passportLocalMongoose to check user is authenticated
  console.log("Arrived at secrets");
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
