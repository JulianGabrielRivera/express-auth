var express = require("express");
var router = express.Router();
const bcryptjs = require("bcryptjs");
const saltRounds = 10;
const User = require("../models/User.model");
const mongoose = require("mongoose");
/* GET users listing. */
router.get("/signup", function (req, res, next) {
  res.render("auth/signup.hbs");
});
router.post("/signup", function (req, res, next) {
  console.log("The form data: ", req.body);

  const { username, email, password } = req.body;
  // our own validation , if we comment this out we get same but the built in errors from mongoose.
  if (!username || !email || !password) {
    res.render("auth/signup", {
      errorMessage:
        "All fields are mandatory. Please provide your username, email and password.",
    });
    return;
  }
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res.status(500).render("auth/signup", {
      errorMessage:
        "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.",
    });
    return;
  }
  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => {
      // extra line we have to use return
      return bcryptjs.hash(password, salt);
    })
    .then((hashedPassword) => {
      return User.create({
        // username: username
        // because the name of username is in model and the destructure is also username then we can just use username here instead of username:username
        username,
        email,
        // passwordHash => this is the key from the User model
        //     ^
        //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
        passwordHash: hashedPassword,
      });
    })
    .then((userFromDB) => {
      console.log("Newly created user is: ", userFromDB);
      res.redirect("/users/profile");
    })
    .catch((error) => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", { errorMessage: error.message });
      } else if (error.code === 11000) {
        res.status(500).render("auth/signup", {
          errorMessage:
            "Username and email need to be unique. Either username or email is already used.",
        });
      } else {
        next(error);
      }
    });
});
// auth.routes.js
// the imports, get and post route remain untouched for now

router.get("/profile", (req, res) => {
  res.render("users/user-profile.hbs");
});

module.exports = router;
