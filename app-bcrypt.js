require('dotenv').config(); //run this at top
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
//const _ = require("lodash"); //For word processing
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
//const md5 = require("md5"); //fast hasher
const bcrypt = require("bcrypt"); //slow hasher
const saltRounds = 10; //how many times to salt pw


const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static('public/'));


// ============= DB Setup =================//
mongoose.connect("mongodb://localhost:27017/secretsDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//For mongoose-encryption
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password'] });
//encrypts on save, decrypts on find


const User = mongoose.model("User", userSchema);

// const welcome = new Post({
//   title: "Welcome!",
//   content: "This is a simple blog website that I made during my web development course. It uses templating with EJS and saves blog posts to a Mongo database."
// });




app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});




app.post("/register", function(req, res) {

  // const newUser = new User({
  //   email: req.body.username,
  //   password: md5(req.body.password) //hash with md5
  // });

  //bcrypt hash
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash
    });

    newUser.save(function(err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets"); //only render secrets from register route
      }
    });
  })
});


app.post("/login", function(req, res) {
  const username = req.body.username;
  // const password = md5(req.body.password); //md5 hash
  const password = req.body.password;

  User.findOne({
    email: username
  }, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        //if (foundUser.password === password){
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if (result === true) {
            res.render("secrets"); //only render secrets from login route
          }
        }); //bcrypt
      };
    };
  });
});




app.listen(3000, function() {
  console.log("app.js running on port 3000");
});
