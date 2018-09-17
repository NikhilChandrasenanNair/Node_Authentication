const passport = require("passport");
const User = require("../models/employee-login.models");
const secret = require("../config/employee.config");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const LocalStrategy = require("passport-local");

// Create Local Strategy
const localLogin = new LocalStrategy(
  { usernameField: "email" },
  (email, password, done) => {
    // Verify this email and password, call done with the user
    // if it is the correct email and password
    // otherwise, call done with false
    User.findOne({ email }, (err, user) => {
      if (err) return done(err);
      if (!user) return done(null, false, { message: "Incorrect Email." });
      // Compare passwords - is `password` equal to user.password?
      user.comparePassword(password, user, (err, isMatch) => {
        if (err) return done(err);
        if (!isMatch)
          return done(null, false, { message: "Incorrect password." });

        return done(null, user);
      });
    });
  }
);

// Setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader("authorization"),
  secretOrKey: secret.secretToken
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
  // See if the user ID in the payload exists in our database
  // If it does, call 'done' with that other
  // otherwise, call done without a user object
  User.findById(payload.sub, (err, user) => {
    if (err) return done(err, false);
    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
