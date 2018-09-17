const User = require("../models/employee-login.models");
const bcrypt = require("bcryptjs");
const jwt = require("jwt-simple");
const nodemailer = require("nodemailer");
const async = require("async");
const crypto = require("crypto");

const secret = require("../config/employee.config");

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, secret.secretToken);
}

exports.login = (req, res, next) => {
  // User has already had their email and password Auth'd
  // We just need to give them a token
  res.send({ token: tokenForUser(req.user) });
};

exports.register = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email) {
    return res.status(422).send({ error: "You must provide email" });
  } else if (!password) {
    return res.status(422).send({ error: "You must provide password" });
  }

  // see if user with a given email exists
  User.findOne({ email: email }, (err, existingUser) => {
    if (err) {
      return next(err);
    }

    // If user with email exist, return error
    if (existingUser) {
      return res.status(422).send({ error: "Email is in use" });
    }

    // if user with email does NOT exist, create and save user record
    const user = new User({
      email,
      password
    });

    // Generate a salt and then callback
    bcrypt.genSalt(10, (err, salt) => {
      if (err) {
        return next(err);
      }
      // Hash our password using salt
      bcrypt.hash(user.password, salt, (err, hash) => {
        if (err) {
          return next(err);
        }

        // overwright plain text password with encrypted passwords
        user.password = hash;
        user.save(err => {
          if (err) {
            return next(err);
          }
          // respond to request indication user was created
          res.json({ token: tokenForUser(user) });
        });
      });
    });
  });
};

exports.forgot = (req, res, next) => {
  async.waterfall(
    [
      function(done) {
        crypto.randomBytes(20, function(err, buf) {
          var token = buf.toString("hex");
          done(err, token);
        });
      },
      function(token, done) {
        const email = req.body.email;
        if (!email) {
          return res.status(422).send({ error: "You must provide email" });
        }
        User.findOne({ email: req.body.email }, function(err, user) {
          if (!user) {
            return res
              .status(422)
              .send({ error: "No account with that email address exists." });
          }

          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000;
          user.save(function(err) {
            done(err, token, user);
          });
        });
      },
      function(token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            type: "OAuth2",
            user: secret.gmail.senderMailId,
            clientId: secret.gmail.clientId,
            clientSecret: secret.gmail.clientSecret,
            refreshToken: secret.gmail.refreshToken,
            accessToken: secret.gmail.accessToken
          }
        });

        var mailOptions = {
          to: user.email,
          from: secret.gmail.senderMailId,
          subject: "Node.js Password Reset",
          text:
            "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
            "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
            "http://" +
            req.headers.host +
            "/reset/" +
            token +
            "\n\n" +
            "If you did not request this, please ignore this email and your password will remain unchanged.\n"
        };
        smtpTransport.sendMail(mailOptions, function(err) {
          if (err) return next(err);

          res.json({ email: `Sent successfully to ${user.email}` });
        });
      }
    ],
    function(err) {
      if (err) return next(err);
    }
  );
};

exports.reset = (req, res) => {
  async.waterfall(
    [
      function(done) {
        User.findOne(
          {
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
          },
          function(err, user) {
            if (!user) {
              return res.redirect("back");
            }

            // Generate a salt and then callback
            bcrypt.genSalt(10, (err, salt) => {
              if (err) {
                return next(err);
              }
              // Hash our password using salt
              bcrypt.hash(req.body.password, salt, (err, hash) => {
                if (err) {
                  return next(err);
                }

                // overwright plain text password with encrypted passwords
                user.password = hash;
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;

                user.save(err => {
                  if (err) {
                    return next(err);
                  }
                  // respond to request indication user was created
                  res.json({ token: tokenForUser(user) });
                  done(err, user);
                });
              });
            });
          }
        );
      },
      function(user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            type: "OAuth2",
            user: secret.gmail.senderMailId,
            clientId: secret.gmail.clientId,
            clientSecret: secret.gmail.clientSecret,
            refreshToken: secret.gmail.refreshToken,
            accessToken: secret.gmail.accessToken
          }
        });

        var mailOptions = {
          to: user.email,
          from: secret.gmail.senderMailId,
          subject: "Your password has been changed",
          text:
            "Hello,\n\n" +
            "This is a confirmation that the password for your account " +
            user.email +
            " has just been changed.\n"
        };

        smtpTransport.sendMail(mailOptions, function(err) {
          if (err) return next(err);

          res.json({ success: "Success! Your password has been changed." });
        });
      }
    ],
    function(err) {
      res.redirect("/");
    }
  );
};

exports.test = (req, res, next) => {
  res.send("Test Controller");
};
