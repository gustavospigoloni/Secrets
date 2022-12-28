require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const findOrCreate = require("mongoose-findorcreate")


const app = express();

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://0.0.0.0:27017/secretsDB");

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/" ,(req, res) => {
    res.render("home");
});


app.route("/register")
.get((req, res) => {
    res.render("register");
})
.post((req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if (err){
            console.log(err);
            res.redirect("/register");
        } else {
             passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
             });
        }
    })
});


app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get('/auth/google/secrets', 
  passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
    res.redirect("/secrets");
});

app.get("/auth/facebook",
  passport.authenticate("facebook", { scope: ["profile"] }));

app.get('/auth/facebook/secrets', 
  passport.authenticate("facebook", { failureRedirect: "/login" }), (req, res) => {
    res.redirect("/secrets");
});


app.route("/login")
.get((req, res) => {
    res.render("login");
})
.post((req, res) => {
    const user = new User ({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) console.log(err);
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
             });
        }
    })
});


app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) console.log(err);
        else res.redirect("/");
    });
});


app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        User.find({"secret": {$ne: null}}, (err, foundUsers) => {
            if (err) console.log(err);
            else {
                if (foundUsers) {
                    res.render("secrets", {foundUsers: foundUsers})
                }
            }
        })
    } else {
        res.redirect("/login");
    }
});


app.route("/submit")
.get((req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})
.post((req, res) => {
    const newSecret = req.body.secret;
    
    User.findById(req.user.id, (err, foundUser) => {
        if (err) console.log(err);
        else {
            if (foundUser){
                foundUser.secret = newSecret;
                foundUser.save();
                res.redirect("/secrets")
            }
        }
    });
});


app.listen(3000, () => {
    console.log("Server running on port 3000");
});